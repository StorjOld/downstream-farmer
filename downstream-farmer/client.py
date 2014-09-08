#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

import requests

from utils import urlify


class DownstreamClient(object):
    def __init__(self, server_url):
        self.server = server_url.strip('/')

    def connect(self, url):
        raise NotImplementedError

    def store_path(self, path):
        raise NotImplementedError

    def get_chunk(self, hash):
        raise NotImplementedError

    def challenge(self, hash, challenge):
        raise NotImplementedError

    def answer(self, hash, hash_answer):
        pass

    def get_challenges(self, filename):
        enc_fname = urlify(os.path.split(filename)[1])
        url = '%s/api/downstream/challenge/%s' % (self.server, enc_fname)
        resp = requests.get(url)

    def answer_challenge(self, filename):
        enc_fname = self._enc_fname(filename)
        raise NotImplementedError