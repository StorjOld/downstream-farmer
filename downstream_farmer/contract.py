import json
import os
import time
import threading

from datetime import datetime, timedelta
import requests
from RandomIO import RandomIO

from .utils import handle_json_response
from .exc import DownstreamError


class DownstreamContract(object):

    def __init__(self,
                 client,
                 hash,
                 seed,
                 size,
                 challenge,
                 expiration,
                 tag,
                 manager,
                 chunk_dir):
        self.hash = hash
        self.seed = seed
        self.size = size
        self.challenge = challenge
        self.expiration = expiration
        self.estimated_interval = expiration - datetime.utcnow()
        self.tag = tag
        self.client = client
        self.answered = False
        self.thread_manager = manager
        self.path = os.path.join(chunk_dir, self.hash)
        self.data_initialized = False
        self.chunk_generation_rate = 0
        self.proof_data = None
        self.file_lock = threading.Lock()

    def __repr__(self):
        return self.hash[:8]

    def generate_data(self):
        start = time.clock()
        RandomIO(self.seed).genfile(self.size, self.path)
        stop = time.clock()
        self.chunk_generation_rate = float(self.size)/float(stop-start)
        self.data_initialized = True

    def cleanup_data(self):
        with self.file_lock:
            if (os.path.isfile(self.path)):
                os.remove(self.path)
            self.data_initialized = False

    def __enter__(self):
        self.generate_data()

    def __exit__(self, type, value, traceback):
        self.cleanup_data()

    def time_remaining(self):
        """Returns the amount of time until this challenge
        is ready to be updated.

        :returns: time til expiration in seconds
        """
        if (self.answered):
            time_til_expiration = self.expiration - datetime.utcnow()
            return time_til_expiration.total_seconds()
        else:
            return -self.estimated_interval.total_seconds()

    def update_challenge(self, block=True):
        """Updates the challenge for this contract

        Checks that existing challenge has expired before getting a new one
        :param block: if block is True, waits until the old challenge has
        expired before getting a new one.  Otherwise, if the old challenge
        has not expired, returns immediately
        """
        if (not self.answered):
            # dont need to update since we haven't answered yet.
            return

        time_til_expiration = self.time_remaining()
        if (time_til_expiration > 0):
            if (block):
                print('Waiting {0} seconds until new challenge is available.'
                      .format(time_til_expiration))
                # contract expiration is in the future...
                # wait til contract expiration
                self.thread_manager.sleep(time_til_expiration)
                if (not self.thread_manager.running):
                    return
            else:
                return

        # now contract should be expired, we can get a new challenge

        url = '{0}/challenge/{1}/{2}'.format(self.client.api_url,
                                             self.client.token,
                                             self.hash)
        try:
            resp = requests.get(url, verify=self.client.requests_verify_arg)
        except:
            raise DownstreamError('Unable to perform HTTP get.')

        try:
            r_json = handle_json_response(resp)
        except DownstreamError:
            raise DownstreamError('Challenge update failed.')

        if ('status' in r_json and r_json['status'] == 'no more challenges'):
            raise DownstreamError(
                'No more challenges for contract {0}'.format(self.hash))

        for k in ['challenge', 'due', 'answered']:
            if (k not in r_json):
                raise DownstreamError('Malformed response from server.')

        self.challenge = self.client.heartbeat.challenge_type().\
            fromdict(r_json['challenge'])
        self.expiration = datetime.utcnow()\
            + timedelta(seconds=int(r_json['due']))
        self.answered = r_json['answered']

    def answer_challenge(self):
        """Answers the challenge.
        """
        if (self.answered):
            # we don't answer challenges that have already been answered
            # there isn't any point
            return

        url = '{0}/answer/{1}/{2}'.format(self.client.api_url,
                                          self.client.token,
                                          self.hash)

        print('Answering challenge for contract {0}...: {1}'.
              format(self.hash[:8], self.challenge.todict()))

        # ok now we will read from file
        with open(self.path, 'rb') as f:
            proof = self.client.heartbeat.prove(f, self.challenge, self.tag)

        print('Sending proof for contract {0}...: {1}'.
              format(self.hash[:8], proof.todict()))

        data = {
            'proof': proof.todict()
        }
        headers = {
            'Content-Type': 'application/json'
        }

        try:
            resp = requests.post(url,
                                 data=json.dumps(data),
                                 headers=headers,
                                 verify=self.client.requests_verify_arg)
        except:
            raise DownstreamError('Unable to perform HTTP post.')

        try:
            r_json = handle_json_response(resp)
        except DownstreamError as ex:
            raise DownstreamError(
                'Challenge answer failed: {0}'.format(str(ex)))

        if ('status' not in r_json):
            raise DownstreamError('Malformed response from server.')

        if (r_json['status'] != 'ok'):
            raise DownstreamError('Challenge response rejected.')

        self.answered = True
    
    
    def update_proof(self):
        """Places pending proof data into proof_data"""
        self.proof_data = self.get_proof()
        if (self.proof_data is not None):
            return True
        else:
            return False
    

    def get_proof(self):
        """Returns the jsonifyable proof of the challenge answer for this contract
        
        :returns: the proof object for this contracts challenge answer,
            as a dictionary:
            {
                'file_hash': 'associated file hash',
                'proof': '...proof object string...'
            }
            or None, if the challenge has already been answered
        """
        if (self.answered):
            # we don't answer challenges that have already been answered
            # there isn't any point
            return None

        # ok now we will read from file
        try:
            with self.file_lock, open(self.path, 'rb') as f:
                proof = self.client.heartbeat.prove(f, self.challenge, self.tag)
        except IOError:
            raise DownstreamError('Unable to open chunk file.')

        data = dict(file_hash=self.hash,
                    proof=proof.todict())
        
        return data
