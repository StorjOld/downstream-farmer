#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

import requests

from utils import urlencode


class DownstreamClient(object):
    def __init__(self, server_url):
        self.server = server_url.strip('/')

    def get_challenges(self, filename):
        enc_fname = urlencode(os.path.split(filename))
        url = '%s/api/downstream/challenge/%s' % (self.server, enc_fname)
        resp = requests.get(url)
