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
