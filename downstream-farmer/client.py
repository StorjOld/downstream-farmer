#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import json
import random
import hashlib

import requests
from heartbeat import Challenge, Heartbeat

from .utils import urlify
from .exc import DownstreamError


class DownstreamClient(object):
    def __init__(self, server_url):
        self.server = server_url.strip('/')
        self.challenges = []
        self.heartbeat = None

    def connect(self, url):
        raise NotImplementedError

    def store_path(self, path):
        raise NotImplementedError

    def get_chunk(self, hash):
        raise NotImplementedError

    def challenge(self, hash, challenge):
        raise NotImplementedError

    def answer(self, hash, hash_answer):
        raise NotImplementedError

    def _enc_fname(self, filename):
        return urlify(os.path.split(filename)[1])

    def get_challenges(self, filename):
        enc_fname = urlify(os.path.split(filename)[1])
        url = '%s/api/downstream/challenge/%s' % (self.server, enc_fname)
        resp = requests.get(url)
        try:
            resp.raise_for_status()
        except Exception as e:
            raise DownstreamError("Error connecting to downstream"
                                  "-node:", e.message)
        _json = resp.json()

        for challenge in _json['challenges']:
            chal = Challenge(challenge.get('block'), challenge.get('seed'))
            self.challenges.append(chal)

    def answer_challenge(self, filename):
        try:
            assert os.path.isfile(filename)
        except AssertionError:
            raise DownstreamError('%s is not a valid file' % filename)

        enc_fname = self._enc_fname(filename)
        raise NotImplementedError

    def random_challenge(self):
        random.choice(self.challenges)