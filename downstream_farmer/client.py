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

import requests
import heartbeat
from datetime import datetime, timedelta

from .utils import handle_json_response, LoadTracker
from .exc import DownstreamError
from .contract import DownstreamContract

heartbeat_types = {'Swizzle': heartbeat.Swizzle.Swizzle,
                   'Merkle': heartbeat.Merkle.Merkle}

api_prefix = '/api/downstream/v1'


class ContractPool(object):

    def __init__(self, manager, contract_thread, wake_ct_on_hb=False):
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
        # wake up the thread
        self.thread.wake()

    def remove_contract(self, contract):
        with self.contracts_lock:
            self.contracts.remove(contract)
        # wake up the contract manager thread in order to get more
        # contracts if necessary
        self.contract_thread.wake()
        contract.cleanup_data()

    def remove_all_contracts(self):
        with self.contracts_lock:
            for c in self.contracts:
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
        self.contract_pools = list()
        self.contract_pools_lock = threading.Lock()
        self.next_pool_idx = 0
        self.contract_thread = None
        self.cert_path = None
        self.verify_cert = True
        self.running = True
        self.thread_manager = manager
        self.chunk_dir = chunk_dir
        self._set_requests_verify_arg()

    def __del__(self):
        self._remove_all_contracts()

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

    def get_contract(self, size=None):
        """Gets a chunk contract from the connected node

        :param size: the maximum size of the contract, not yet used
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

        if ('status' in r_json and r_json['status'] == 'no chunks available'):
            raise DownstreamError('No chunks available.')

        for k in ['file_hash', 'seed', 'size', 'challenge', 'tag', 'due']:
            if (k not in r_json):
                raise DownstreamError('Malformed response from server.')

        # perform a size check
        if (self.get_total_size() + r_json['size'] > self.desired_size):
            raise DownstreamError('Server sent excessively sized chunk.')

        contract = DownstreamContract(
            self,
            r_json['file_hash'],
            r_json['seed'],
            r_json['size'],
            self.heartbeat.challenge_type().fromdict(r_json['challenge']),
            datetime.utcnow() + timedelta(seconds=int(r_json['due'])),
            self.heartbeat.tag_type().fromdict(r_json['tag']),
            self.thread_manager,
            self.chunk_dir)

        return contract

    def get_total_size(self):
        """Returns the total size of all the current contracts
        """
        total = 0
        with self.contract_pools_lock:
            for c in self.contract_pools:
                total += c.get_total_size()
        return total

    def contract_count(self):
        count = 0
        with self.contract_pools_lock:
            for c in self.contract_pools:
                count += c.contract_count()
        return count

    def heartbeat_count(self):
        count = 0
        with self.contract_pools_lock:
            for c in self.contract_pools:
                count += c.heartbeat_count
        return count

    def _add_contract(self, contract, wake_on_hb=False):
        """Used internally to add a contract to the client.
        Finds a contract pool to add the contract to, or if
        all contract pools are too heavily loaded, creates a new contract
        pool.
        :param contract: the contract to add
        :param number: the number of challenges to answer per contract
        """
        # finds a contract pool to add this contact to
        # if there aren't any loaded under 50%, adds a new one
        candidate_pools = dict()
        for p in self.contract_pools:
            load = p.get_average_load()
            # print('Contract pool {0} is loaded at {1}%'
            #       .format(p, round(load*100, 2)))
            if (load < 0.5):
                candidate_pools[load] = p

        if (len(candidate_pools) > 0):
            p = candidate_pools[min(candidate_pools.keys())]
            # print('Adding new contract {0} to contract pool {1}'
            #       .format(contract, p))
            p.add_contract(contract)
        else:
            # start a new thread
            contract_pool = ContractPool(self.thread_manager,
                                         self.contract_thread,
                                         wake_on_hb)
            self.contract_pools.append(contract_pool)
            print('Starting a new contract pool (Pool Count: {0})'.format(
                len(self.contract_pools)))
            contract_pool.start()
            contract_pool.add_contract(contract)

    def _remove_all_contracts(self):
        with self.contract_pools_lock:
            for c in self.contract_pools:
                c.remove_all_contracts()
            self.contract_pools = list()

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
            # first attempts to obtain the full contract size
            try:
                while (self.thread_manager.running
                       and self.get_total_size() < self.desired_size):
                    print('Contracts: {0}, Total size: {1}/{2}'.
                          format(self.contract_count(),
                                 self.get_total_size(),
                                 self.desired_size))
                    size_to_fill = self.desired_size - self.get_total_size()
                    contract = self.get_contract(size_to_fill)
                    print('Obtained contract {0}... for {1} bytes'.format(
                        contract.hash[:8], contract.size))
                    self._add_contract(contract, wake_on_hb)
                    print('Capacity filled {0}%'.format(
                        round(self.get_total_size() /
                              self.desired_size * 100, 2)))
            except DownstreamError as ex:
                if (self.contract_count() == 0):
                    print('Unable to obtain a contract: {0}'.format(str(ex)))
                    if (retry):
                        continue
                    else:
                        self.thread_manager.signal_shutdown()
                        return
                else:
                    print('No chunks of the correct size available now.')
            if (not self.thread_manager.running):
                # we already exited.  contract_manager needs to return now
                return
            # wait until we need to obtain a new contract
            if (not online_already):
                print('Your farmer is online.')
                online_already = True
            self.contract_thread.wait(30)

            if (number is not None and self.heartbeat_count() >= number):
                # signal a shutdown, and return
                print('Heartbeat number requirement met.')
                self.thread_manager.signal_shutdown()
                return

    def run_async(self, retry=False, number=None):
        """Starts the contract management loop

        :param retry: whether to retry on obtaining a contract upon failure
        :param number: the number of challenges to answer
        """
        # create the contract manager
        self.contract_thread = self.thread_manager.create_thread(
            target=self._run_contract_manager,
            args=(retry, number))

        # challenge threads will be created as needed

        self.contract_thread.start()
