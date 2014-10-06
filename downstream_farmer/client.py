#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import io
import os
import json
import random
import hashlib

import requests
from heartbeat import Heartbeat
from RandomIO import RandomIO

from .utils import urlify, handle_json_response
from .exc import DownstreamError

class Contract(object):
    def __init__(self, hash, seed, size, challenge, tag):
        self.hash = hash
        self.seed = seed
        self.size = size
        self.challenge = challenge
        self.tag = tag

class DownstreamClient(object):
    def __init__(self, address):
        self.address = address
        self.token = ''
        self.server = ''
        self.heartbeat = None
        self.contract = None

    def connect(self, url):
        self.server = url.strip('/')
        url = '{0}/api/downstream/new/{1}'.format(self.server, self.address)
        
        resp = requests.get(url)
        r_json = handle_json_response(resp)
        
        for k in ['token','heartbeat']:
            if (k not in r_json):
                raise DownstreamError('Malformed response from server.')
        
        self.token = r_json['token']
        self.heartbeat = Heartbeat.fromdict(r_json['heartbeat'])

    def get_chunk(self):
        url = '{0}/api/downstream/chunk/{1}'.format(self.server, self.token)

        resp = requests.get(url)
        r_json = handle_json_response(resp)

        for k in ['file_hash', 'seed', 'size', 'challenge', 'tag']:
            if (k not in r_json):
                raise DownstreamError('Malformed response from server.')
        
        self.contract = Contract(
            r_json['file_hash'],
            r_json['seed'],
            r_json['size'],
            Heartbeat.challenge_type().fromdict(r_json['challenge']),
            Heartbeat.tag_type().fromdict(r_json['tag']))

    def answer_challenge(self):
        if (self.contract is None):
            raise DownstreamError('No contract to answer.')
    
        contract = self.contract
    
        url = '{0}/api/downstream/answer/{1}/{2}'.format(self.server,
                                                         self.token,
                                                         contract.hash)

        with io.BytesIO(RandomIO(contract.seed).read(contract.size)) as f:
            proof = self.heartbeat.prove(f, contract.challenge, contract.tag)

        data = { 
            'proof': proof.todict() 
        }
        headers = {
            'Content-Type': 'application/json'
        }
        
        resp = requests.post(url, data=json.dumps(data), headers=headers)
        r_json = handle_json_response(resp)
        
        if ('status' not in r_json):
            raise DownstreamError('Malformed response from server.')
        
        if (r_json['status'] != 'ok'):
            raise DownstreamError('Challenge response rejected.')

