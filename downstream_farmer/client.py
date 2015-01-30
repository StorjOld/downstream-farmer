#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import os
import sys
import binascii
import hashlib
import json
import threading
import traceback
import time

import requests
import heartbeat
from datetime import datetime, timedelta
from collections import deque

from .utils import handle_json_response, LoadTracker, ThreadPool, sizeof_fmt, BurstQueue
from .exc import DownstreamError
from .contract import DownstreamContract

heartbeat_types = {'Swizzle': heartbeat.Swizzle.Swizzle,
                   'Merkle': heartbeat.Merkle.Merkle}

api_prefix = '/api/downstream/v1'
        

class ContractPool(object):

    def __init__(self, manager, contract_thread, contract_index, wake_ct_on_hb=False):
        self.contracts = list()
        self.contracts_lock = threading.Lock()
        self.thread_manager = manager
        self.thread = self.thread_manager.create_thread(
            target=self._run_challenge_response_loop)
        self.contract_thread = contract_thread
        self.load_tracker = LoadTracker()
        self.id = binascii.hexlify(os.urandom(4)).decode()
        self.heartbeat_count = 0
        self.wake_ct_on_hb = wake_ct_on_hb
        self.contract_index = contract_index        

    def __del__(self):
        self.remove_all_contracts()

    def __repr__(self):
        return self.id

    def start(self):
        self.thread.start()

    def get_total_size(self):
        """Returns the total size of all the current contracts
        """
        with self.contracts_lock:
            if (len(self.contracts) > 0):
                return sum(c.size for c in self.contracts)
            else:
                return 0

    def contract_count(self):
        with self.contracts_lock:
            return len(self.contracts)

    def get_average_load(self):
        """Reutrns the loading of this thread
        :returns: the percent load (work time / total time)
        """
        return self.load_tracker.load()

    def add_contract(self, contract):
        """This starts the specified contract
        :param contract: contract to run
        """
        contract.generate_data()
        with self.contracts_lock:
            self.contracts.append(contract)
        self.contract_index.add_contract(contract)
        # wake up the thread
        self.thread.wake()

    def remove_contract(self, contract):
        with self.contracts_lock:
            self.contracts.remove(contract)
        self.contract_index.remove_contract(contract)
        # wake up the contract manager thread in order to get more
        # contracts if necessary
        self.contract_thread.wake()
        contract.cleanup_data()

    def remove_all_contracts(self):
        with self.contracts_lock:
            for c in self.contracts:
                self.contract_index.remove_contract(c)
                c.cleanup_data()
            self.contracts = list()

    def get_next_contract(self):
        """Finds the next contract to update and answer based on
        time til expiration
        """
        next_contract = None
        least_time = None
        with self.contracts_lock:
            for c in self.contracts:
                time_on_this_contract = c.time_remaining()
                if (least_time is None or time_on_this_contract < least_time):
                    next_contract = c
                    least_time = time_on_this_contract
        return next_contract

    def _run_challenge_response_loop(self):
        self.load_tracker.start_work()
        while (self.thread_manager.running):
            try:
                next_contract = self.get_next_contract()
                if (next_contract is None):
                    # no contracts.  wait until there are contracts available
                    self.thread.wait()
                    continue

                time_to_wait = next_contract.time_remaining()

                if (time_to_wait > 0):
                    self.load_tracker.finish_work()
                    self.thread.wait(time_to_wait + 2)
                    self.load_tracker.start_work()
                    continue

                try:
                    # update the challenge.  don't block if for any reason
                    # we would (which we shouldn't anyway)
                    next_contract.update_challenge(False)

                    # answer the challenge
                    next_contract.answer_challenge()

                    self.heartbeat_count += 1

                    if (self.wake_ct_on_hb):
                        self.contract_thread.wake()

                except DownstreamError as ex:
                    # challenge answer failed, remove this contract
                    print('Challenge update/answer failed: {0}, '
                          'dropping contract {1}'.
                          format(str(ex), next_contract.hash))

                    self.remove_contract(next_contract)
                    continue
            except:
                print('Unexpected error: {0}'.format(sys.exc_info()[1]))
                traceback.print_exc()
                self.remove_all_contracts()
                self.thread_manager.signal_shutdown()
                return

class DownstreamClient(object):

    marks = {'proving': 1,
             'updating': 2,
             'submitting': 4}

    def __init__(self,
                 url,
                 token,
                 address,
                 size,
                 msg,
                 sig,
                 manager,
                 chunk_dir):
        self.server = url.strip('/')
        self.api_url = self.server + api_prefix
        self.token = token
        self.address = address
        self.desired_size = size
        self.msg = msg
        self.sig = sig
        self.heartbeat = None
        
        # going away
        self.contract_pools = list()
        self.contract_pools_lock = threading.Lock()
        self.next_pool_idx = 0
        self.queued_proofs_lock = threading.Lock()
        self.queued_proofs = dict()
        
        
        self.contract_thread = None
        self.heartbeat_thread = None
        self.cert_path = None
        self.verify_cert = True
        self.running = True
        self.thread_manager = manager
        self.chunk_dir = chunk_dir
        self._set_requests_verify_arg()
        
        self.contracts_lock = threading.RLock()
        self.contracts = dict()
        self.heartbeat_count_lock = threading.Lock()
        self.heartbeat_count = 0
        # response margin defaults to 20.  contracts will begin to be answered
        # at least this number of seconds before they expire
        self.response_margin = 20
        # update margin defaults to 20.  contracts will begin to be updated
        # no later than this amount of time after it is possible to update them
        # the margin between then a contract is updated and when it must be 
        # proven will be dependent on the interval.  if the interval is less
        # than the update_margin, the contract will fail.
        self.update_margin = 20
        # status of the contract, used for determining whether to update or what
        self.contract_status = dict()
        self.contract_status_lock = threading.Lock()
        # this is the initial estimated onboard rate, that determines how fast the
        # farmer can onboard contracts in bytes/second
        # this provides an initial estimate.... it will be dependent on disk and
        # or download speeds in actual applications
        self.estimated_onboard_speed = 2000000
        self.estimated_contract_interval = 60
        
        self.submission_queue = BurstQueue()
        self.update_queue = BurstQueue()

    def set_cert_path(self, cert_path):
        """Sets the path of a CA-Bundle to use for verifying requests
        """
        self.cert_path = cert_path
        self._set_requests_verify_arg()

    def set_verify_cert(self, verify_cert):
        """Sets whether or not to verify the ssl certificate
        """
        self.verify_cert = verify_cert
        self._set_requests_verify_arg()

    def _set_requests_verify_arg(self):
        """Sets the appropriate requests verify argument
        """
        if (self.verify_cert):
            self.requests_verify_arg = self.cert_path
        else:
            self.requests_verify_arg = False

    def connect(self):
        """Connects to a downstream-node server.
        """
        if (self.token is None):
            if (self.address is None):
                raise DownstreamError(
                    'If no token is specified, address must be.')
            # get a new token
            url = '{0}/new/{1}'.\
                format(self.api_url, self.address)
            # if we have a message/signature to send, send it
            if (self.msg != '' and self.sig != ''):
                data = {
                    "message": self.msg,
                    "signature": self.sig
                }
                headers = {
                    'Content-Type': 'application/json'
                }
                resp = requests.post(
                    url,
                    data=json.dumps(data),
                    headers=headers,
                    verify=self.requests_verify_arg)
            else:
                # otherwise, just normal request
                resp = requests.get(url, verify=self.requests_verify_arg)
        else:
            # try to use our token
            url = '{0}/heartbeat/{1}'.\
                format(self.api_url, self.token)

            resp = requests.get(url, verify=self.requests_verify_arg)

        try:
            r_json = handle_json_response(resp)
        except DownstreamError as ex:
            raise DownstreamError('Unable to connect: {0}'.
                                  format(str(ex)))

        for k in ['token', 'heartbeat', 'type']:
            if (k not in r_json):
                raise DownstreamError('Malformed response from server.')

        if r_json['type'] not in heartbeat_types.keys():
            raise DownstreamError('Unknown Heartbeat Type')

        self.token = r_json['token']
        self.heartbeat \
            = heartbeat_types[r_json['type']].fromdict(r_json['heartbeat'])

        # we can calculate farmer id for display...
        token = binascii.unhexlify(self.token)
        token_hash = hashlib.sha256(token).hexdigest()[:20]
        print('Confirmed token: {0}'.format(self.token))
        print('Farmer id: {0}'.format(token_hash))

    def get_contracts(self, size=None):
        """Gets a chunk contract from the connected node

        :param size: the maximum size of the contract
        :returns: a list of obtained contracts
        """
        url = '{0}/chunk/{1}'.format(self.api_url, self.token)
        if (size is not None):
            url += '/{0}'.format(size)

        resp = requests.get(url, verify=self.requests_verify_arg)

        try:
            r_json = handle_json_response(resp)
        except DownstreamError as ex:
            # can't handle an invalid token
            raise DownstreamError('Unable to get token: {0}'.
                                  format(str(ex)))
                                  
        if ('chunks' not in r_json or not isinstance(r_json['chunks'], list)):
            raise DownstreamError('Malformed response from server.')
        
        contracts = list()
        
        for chunk in r_json['chunks']:
            
            for k in ['file_hash', 'seed', 'size', 'challenge', 'tag', 'due']:
                if (k not in chunk):
                    print('Malformed chunk sent from server.')
                    continue

            contract = DownstreamContract(
                self,
                chunk['file_hash'],
                chunk['seed'],
                chunk['size'],
                self.heartbeat.challenge_type().fromdict(chunk['challenge']),
                datetime.utcnow() + timedelta(seconds=int(chunk['due'])),
                self.heartbeat.tag_type().fromdict(chunk['tag']),
                self.thread_manager,
                self.chunk_dir)

            contracts.append(contract)
        
        return contracts
    
    def update_challenges_async__(self):
        """Updates all the challenges for this farmer
        """
        # figure out if any contracts need to be updated
        to_update = self.to_update()
        
        if (len(to_update) == 0):
            return
        
        for c in to_update:
            self._mark(c, self.marks['updating'])
    
        self.worker_pool.put_work(self.update_challenges, (to_update,))
    
    def get_total_size(self):
        total = 0
        with self.contracts_lock:
            return sum([c.size for c in self.contracts.values()])

    def contract_count(self):
        with self.contracts_lock:
            return len(self.contracts)
    
    def heartbeat_count(self):
        return self.heartbeat_count
            
    def _add_contract(self, contract):
        with self.contracts_lock:
            contract.generate_data()
            self.contracts[contract.hash] = contract
    
    def _remove_all_contracts(self):
        # print('{0} : enter _remove_all_contracts'.format(threading.current_thread()))
        to_remove = list()
        with self.contracts_lock:
            for c in self.contracts.values():
                to_remove.append(c)
        for c in to_remove:
            self._remove_contract(c)
        # print('{0} : exit _remove_all_contracts'.format(threading.current_thread()))
                
    def _remove_contract(self, contract):
        # print('{0} : enter _remove_contract'.format(threading.current_thread()))
        with self.contracts_lock:
            if (contract.hash in self.contracts):
                contract.cleanup_data()
                del self.contracts[contract.hash]
        # print('{0} : exit _remove_contract'.format(threading.current_thread()))
    
    def _remove_contract_by_hash(self, contract_hash):        
        with self.contracts_lock:
            if (contract_hash in self.contracts):
                self._remove_contract(self.contracts[contract_hash])

    def _get_average_chunk_generation_rate(self):        
        with self.contracts_lock:
            if (len(self.contracts) > 0):
                total = sum([c.chunk_generation_rate for c in self.contracts.values()])
                return float(total) / float(len(self.contracts))
            else:
                return self.estimated_onboard_speed

    def _get_average_contract_interval(self):
        with self.contracts_lock:
            if (len(self.contracts) > 0):
                total = sum([c.estimated_interval.total_seconds() for c in self.contracts.values()])
                return float(total) / float(len(self.contracts))
            else:
                return self.estimated_contract_interval

    def _size_to_fill(self):
        """Returns the size to request this round from verification node
        Estimates disk write speed and average contract interval to
        yield the correct size for the next batch
        """
        total_margin = self.update_margin
        desired_write_time = self._get_average_contract_interval() - total_margin
        # print('Desired write time: {0} seconds'.format(desired_write_time))
        average_gen_rate = self._get_average_chunk_generation_rate()
        # print('Average generation rate: {0} bytes/second'.format(average_gen_rate))
        # half the size just to account for other overhead in producing challenges
        # etc.
        max_obtainable_size = int(average_gen_rate * desired_write_time * 0.5)
        size_needed = self.desired_size - self.get_total_size()
        if (size_needed <= max_obtainable_size):
            return size_needed
        else:
            return max_obtainable_size

    def _run_contract_manager(self, retry=False, number=None):
        """This loop will maintain the desired total contract size, if
        possible
        :param retry: whether to retry if unable to obtain any contracts
        :param number: the number of challenges to answer (for each contract)
            it will perform at least this number of heartbeats and then exit,
            but it may perform more heartbeats depending on the size of the
            requested contracts
        """
        online_already = False
        # we want to wake up on every heart beat in order to check if we have
        # reached our heartbeat goal.  otherwise, don't worry about it
        wake_on_hb = (True if number is not None else False)

        while (self.thread_manager.running):
            size_to_fill = self._size_to_fill()
            while (self.thread_manager.running and size_to_fill > 0):
                print('Requesting chunks to fill {0}'
                      .format(sizeof_fmt(size_to_fill)))
                contracts = self.get_contracts(size_to_fill)
                obtained_size = sum([c.size for c in contracts])
                if (obtained_size > size_to_fill):
                    raise DownstreamError('Server sent too much chunk data,' 
                                          'size exceeded. Rejecting data.')
                print('Obtained {0} contracts for a total size of {1}'.format(
                    len(contracts), sizeof_fmt(obtained_size)))
                if (len(contracts) > 0):
                    for contract in contracts:
                        self._add_contract(contract)
                        # and begin proving this contract
                        self._put_proof(contract)
                    print('Contracts: {0}, Total size: {1}/{2}'.
                          format(self.contract_count(),
                                 sizeof_fmt(self.get_total_size()),
                                 sizeof_fmt(self.desired_size)))
                    print('Capacity filled {0}%'.format(
                        round(float(self.get_total_size()) /
                              float(self.desired_size) * 100.0, 3)))
                else:
                    break

                size_to_fill = self._size_to_fill()
            
            if (not self.thread_manager.running):
                # we already exited.  contract_manager needs to return now
                break
            # wait until we need to obtain a new contract
            if (not online_already):
                print('Your farmer is online.')
                online_already = True
            self.contract_thread.wait(30)

            if (number is not None and self.heartbeat_count() >= number):
                # signal a shutdown, and return
                print('Heartbeat number requirement met.')
                self.thread_manager.signal_shutdown()
                break

        # contract manager is done, remove all contracts
        self._remove_all_contracts()
    
    def _put_proof(self, contract):
        #print('Scheduling proof for contract {0}.'.format(contract))
        self.worker_pool.put_work(self._prove, (contract, ))
    
    def _put_proof__(self, contract):
        """Calculates a proof for the specified contract and puts it into the
        proof queue
        """
        try:
            # print('Getting proof for {0}'.format(contract))
            proof = contract.get_proof()
        except DownstreamError as ex:
            print('Unable to fulfill contract: {0}'.format(str(ex)))
            self._remove_contract(contract)
            return

        if (proof is not None):
            with self.queued_proofs_lock:
                self.queued_proofs[contract] = proof
        else:
            print('Proof for contract {0} was not available.'
                  .format(contract))
                
    def _mark__(self, contract, status):
        with self.contract_status_lock:
            if (contract in self.contract_status):
                self.contract_status[contract] |= status
            else:
                self.contract_status[contract] = status
            
    def _unmark__(self, contract, status=None):         
        with self.contract_status_lock:
            if (contract in self.contract_status):
                if (status is not None):
                    self.contract_status[contract] &= ~status
                else:
                    del self.contract_status[contract]

    def _get_mark__(self, contract, status=None):
        with self.contract_status_lock:
            if (contract in self.contract_status):
                if (status is not None):
                    return (self.contract_status[contract] & status)
                else:
                    return self.contract_status[contract]
            else:
                return None
    
    def _get_tally__(self):
        tally = {k: 0 for k in self.marks.keys()}
        with self.contract_status_lock:
            for c in self.contract_status.values():
                for k in self.marks.keys():
                    if self.marks[k] & c:
                        tally[k] += 1
        return tally
                
    def _perform_proofs_async__(self):
        """Queues the next challenges to be answered by the worker threads
        """
        with self.contracts_lock:
            unanswered_contracts = [
                c for c in self.contracts.values() 
                if not c.answered and not self._get_mark(c,
                    self.marks['proving'])]
        for contract in unanswered_contracts:
            self._mark(contract, self.marks['proving'])
            self.worker_pool.put_work(self._put_proof, (contract, ))
    
    def _contract_due__(self, contract):
        return ((contract.expiration - timedelta(seconds=self.response_margin))
                <= datetime.utcnow())
    
    def _get_next_action_time__(self):
        """Gets the next contract expiration time."""
        earliest = None
        with self.contracts_lock:
            for contract in self.contracts.values():
                if (contract.answered):
                    # next action is to update
                    if (self._get_mark(contract, self.marks['updating'])):
                        # if we are already updating, continue
                        continue
                    # contract is answered, therefore, we must wait until after
                    # expiration time to get an update
                    # we can wait some margin afterwards to 
                    # try to group contracts more
                    time = (contract.expiration
                            + timedelta(seconds=self.update_margin))
                else:
                    # next action is to submit
                    if (self._get_mark(contract, self.marks['submitting'])):
                        # if we are already submitting, continue
                        continue
                    time = (contract.expiration 
                            - timedelta(seconds=self.response_margin))
                if (earliest is None or time < earliest):
                    earliest = time
        return earliest
    
    def _collect_and_send_proofs_async__(self):
        """Collects all the calculated proofs and sends them to the
        verification node"""
        
        # determine if any of these proofs are urgently due
        # if so, send all of them
        with self.queued_proofs_lock:
            any_due = any([self._contract_due(c) for c in self.queued_proofs.keys()])
            
        if (not any_due):
            return
        
        with self.queued_proofs_lock:
            proofs = list(self.queued_proofs.values())
            self.queued_proofs = dict()
        
        if (len(proofs) == 0):
            print('warning: this should not happen')
            return
            
        for p in proofs:
            self._mark(self.contracts[p['file_hash']], self.marks['submitting'])
            
        self.worker_pool.put_work(self._collect_and_send_proofs, (proofs, ))
    
    def _collect_and_send_proofs__(self, proofs):

        start = time.clock()
        url = '{0}/answer/{1}'.format(self.api_url,
                                      self.token)
            
        data = {
            'proofs': proofs
        }
        headers = {
            'Content-Type': 'application/json'
        }

        
        #print('Submitting {0} proofs...'.format(len(proofs)))
        
        try:
            resp = requests.post(url,
                                 data=json.dumps(data),
                                 headers=headers,
                                 verify=self.requests_verify_arg)
        except:
            raise DownstreamError('Unable to perform HTTP post.')

        try:
            r_json = handle_json_response(resp)
        except DownstreamError as ex:
            raise DownstreamError(
                'Challenge answer failed: {0}'.format(str(ex)))

        if ('report' not in r_json or not isinstance(r_json['report'], list)):
            raise DownstreamError('Malformed response from server.')

        successes = 0
            
        for contract_report in r_json['report']:
            if ('file_hash' not in contract_report
                or contract_report['file_hash'] not in self.contracts):
                # fail nicely with a malformed contract report
                print('Warning: Unknown contract report item.')
                continue
            
            contract = self.contracts[contract_report['file_hash']]
                
            if ('error' in contract_report):
                print('Error answering challenge: "{0}", '
                      'dropping contract {1}.'.
                      format(contract_report['error'],
                             contract))
                self._remove_contract(contract)
                continue
            if ('status' not in contract_report or contract_report['status'] != 'ok'):
                print('No status for contract {0}, dropping.'
                      .format(contract))
                self._remove_contract(contract)
                continue
            
            # everything seems to be in order for this contract
            # and now, once a new challenge is obtained, this contract can 
            # be answered again
            contract.answered = True
            successes += 1
            self.heartbeat_count += 1
            self._unmark(contract, self.marks['submitting']|self.marks['proving'])
        
        stop=time.clock()
        print('Submitted {0} proofs successfully in {1} seconds'.format(successes, round(stop-start,3)))
        # and wake heartbeat manager again
        self.heartbeat_thread.wake()
    
    def _run_heartbeat_manager__(self):
        while self.thread_manager.running:
            while self.thread_manager.running:
                # perform proofs
                self._perform_proofs_async()
            
                now = datetime.utcnow()
                next_action_time = self._get_next_action_time()
                if (next_action_time is not None):                    
                    if (next_action_time <= now):
                        # need to take action
                        break
                    # otherwise, sleep until we need to
                    seconds_to_wait = (next_action_time - now).total_seconds()
                else:
                    # no contracts yet, just wait until we have contracts
                    seconds_to_wait = None

                # this thread will also be awoken when a new contract is added
                # so we will catch any short interval contracts
                # print('heartbeat manager waiting {0} seconds to take action'
                #       .format(seconds_to_wait))
                self.thread_manager.sleep(seconds_to_wait)
            
            if (not self.thread_manager.running):
                break
            
            # now, send proofs
            self._collect_and_send_proofs_async()
            
            # perform an update
            self.update_challenges_async()
            
            # perform heartbeat actions
            # print stats
            tally = self._get_tally()
            print('Proving: {0}, Updating: {1}, Idle: {2}'
                  .format(tally['submitting'],
                          tally['updating'],
                          self.contract_count()
                          -tally['submitting']
                          -tally['updating']))
    
    def _prove(self, contract):
        """Calculates a proof for the specified contract and puts it into the
        proof queue
        """
        try:
            proven = contract.update_proof()
        except DownstreamError as ex:
            print('Unable to fulfill contract: {0}'.format(str(ex)))
            self._remove_contract(contract)
            return

        if (proven):
            submission_time = (contract.expiration 
                               - timedelta(seconds=self.response_margin))
            #print('Putting {0} into submission queue.'.format(contract))
            self.submission_queue.put(contract, submission_time)
        else:
            print('Proof for contract {0} was not available.'
                  .format(contract))

        self.heartbeat_thread.wake()
    
    def _submit(self, contracts):
        """Submits the specified contracts
        """
        start = time.clock()
        
        url = '{0}/answer/{1}'.format(self.api_url,
                                      self.token)

        proofs = [c.proof_data for c in contracts]
        contract_dict = {c.hash: c for c in contracts}
        
            
        data = {
            'proofs': proofs
        }
        headers = {
            'Content-Type': 'application/json'
        }
        
        try:
            resp = requests.post(url,
                                 data=json.dumps(data),
                                 headers=headers,
                                 verify=self.requests_verify_arg)
        except:
            raise DownstreamError('Unable to perform HTTP post.')

        try:
            r_json = handle_json_response(resp)
        except DownstreamError as ex:
            raise DownstreamError(
                'Challenge answer failed: {0}'.format(str(ex)))

        if ('report' not in r_json or not isinstance(r_json['report'], list)):
            raise DownstreamError('Malformed response from server.')

        submitted = set()
            
        for contract_report in r_json['report']:
            if ('file_hash' not in contract_report
                or contract_report['file_hash'] not in contract_dict):
                # fail nicely with a malformed contract report
                print('Warning: Unexpected contract report.')
                continue
            
            contract = contract_dict[contract_report['file_hash']]
                
            if ('error' in contract_report):
                print('Error answering challenge for contract{0}: {1}, '
                      .format(contract, contract_report['error']))
                continue
            if ('status' not in contract_report or contract_report['status'] != 'ok'):
                print('No status for contract {0}'
                      .format(contract))
                continue
            
            # everything seems to be in order for this contract
            # and now, once a new challenge is obtained, this contract can 
            # be answered again
            contract.answered = True
            submitted.add(contract)
            with self.heartbeat_count_lock:
                self.heartbeat_count += 1
        
        stop=time.clock()
        print('Submitted {0} proofs successfully in {1} seconds'.format(len(submitted), round(stop-start,3)))
        
        # place submitted proofs in update queue
        for c in contracts:
            if (c not in submitted):
                print('Contract {0} not successfully submitted, dropping'
                      .format(c))
                self._remove_contract(c)
            else:
                #print('Putting {0} into update queue.'.format(c))
                ready_time = c.expiration
                update_time = (c.expiration
                               + timedelta(seconds=self.update_margin))
                self.update_queue.put(c, update_time, ready_time)
        
        # and wake heartbeat manager again
        self.heartbeat_thread.wake()
    
    def _update(self, contracts):
        
        start=time.clock()
        
        hashes = [c.hash for c in contracts]
        
        url = '{0}/challenge/{1}'.format(self.api_url,
                                         self.token)
                                         
        data = {
            'hashes': hashes
        }
        headers = {
            'Content-Type': 'application/json'
        }
        try:
            resp = requests.post(url,
                                 data=json.dumps(data),
                                 headers=headers,
                                 verify=self.requests_verify_arg)
        except:
            raise DownstreamError('Unable to perform HTTP post.')

        try:
            r_json = handle_json_response(resp)
        except DownstreamError:
            raise DownstreamError('Challenge update failed.')

        if 'challenges' not in r_json:
            raise DownstreamError('Malformed response from server.')
            
        # challenges is in r_json
        challenges = r_json['challenges']
        updated = set()

        for challenge in challenges:
            if ('file_hash' not in challenge):
                raise DownstreamError('Malformed response from server.')            
            
            try:
                contract = self.contracts[challenge['file_hash']]
            except KeyError:
                print('Warning: Unexpected challenge update.')
                continue
            
            if ('error' in challenge or 'status' in challenge):
                if 'error' in challenge:
                    message = challenge['error']
                else:
                    message = challenge['status']
                print('Couldn\'t update contract {0}: {1}'
                      .format(contract, message))
                continue
            
            for k in ['challenge', 'due', 'answered']:
                if (k not in challenge):
                    print('Warning: Malformed challenge for contract {0}'
                          .format(contract))
                    continue
            
            contract.challenge = self.heartbeat.challenge_type().\
                fromdict(challenge['challenge'])
            contract.expiration = datetime.utcnow()\
                + timedelta(seconds=int(challenge['due']))
            contract.answered = challenge['answered']
            
            updated.add(contract)
        
        stop=time.clock()
        print('Updated {0} contracts in {1} seconds'
              .format(len(updated), round(stop-start,3)))

        for c in contracts:
            if (c not in updated):
                print('Contract {0} not updated, dropping'
                      .format(c))
                self._remove_contract(c)
            else:
                self._put_proof(c)
        
        # dont need to wake heartbeat manager because we didn't put anything into a queue

    
    def _run_heartbeat_manager(self):
        while self.thread_manager.running:
            # we are managing two BurstQueues.
            # when a contract is obtained or updated, it is proven
            # after being proven, it is placed into the submission queue
            # after being submitted, it is put into the update queue
            # after being updated, it is proven again and the cycle repeats
            contracts_to_submit = self.submission_queue.get()
            
            if (len(contracts_to_submit) > 0):
                print('Submitting {0} contracts'.format(len(contracts_to_submit)))
                self.worker_pool.put_work(self._submit, (contracts_to_submit, ))
            
            contracts_to_update = self.update_queue.get()
            
            if (len(contracts_to_update) > 0):
                print('Updating {0} contracts'.format(len(contracts_to_update)))
                self.worker_pool.put_work(self._update, (contracts_to_update, ))
            
            next = [self.submission_queue.next_due(),
                    self.update_queue.next_due()]
            
            next = [n for n in next if n is not None]
            
            if (len(next) > 0):
                seconds_to_sleep = (min(next) - datetime.utcnow()).total_seconds()
            else:
                seconds_to_sleep = None
                        
            self.thread_manager.sleep(seconds_to_sleep)
            

    def run_async(self, retry=False, number=None):
        """Starts the contract management loop

        :param retry: whether to retry on obtaining a contract upon failure
        :param number: the number of challenges to answer
        """
        # create the contract manager
        self.contract_thread = self.thread_manager.create_thread(
            name='ContractThread',
            target=self._run_contract_manager,
            args=(retry, number))
            
        # create the heartbeat manager
        self.heartbeat_thread = self.thread_manager.create_thread(
            name='HeartbeatThread',
            target=self._run_heartbeat_manager)

        # create the thread pool for challenges
        self.worker_pool = ThreadPool(self.thread_manager, 1)

        self.worker_pool.start()
        self.heartbeat_thread.start()
        self.contract_thread.start()
