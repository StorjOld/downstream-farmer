import json
import os

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

    def __repr__(self):
        return self.hash

    def generate_data(self):
        RandomIO(self.seed).genfile(self.size, self.path)

    def cleanup_data(self):
        if (os.path.isfile(self.path)):
            os.remove(self.path)

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

        # ok now we will read from file
        with open(self.path, 'rb') as f:
            proof = self.client.heartbeat.prove(f, self.challenge, self.tag)

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
