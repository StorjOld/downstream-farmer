#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse

from .client import DownstreamClient
from .exc import ConnectError

try:
    from urllib2 import urlopen, URLError
except ImportError:
    from urllib.request import urlopen
    from urllib.error import URLError


def check_connectivity(url):
        """ Check to see if we even get a connection to the server.
        https://stackoverflow.com/questions/3764291/checking-network-connection
        """
        try:
            urlopen(url, timeout=2)
        except URLError:
            raise ConnectError("Could not connect to server.")


def eval_args(args):
    try:
        check_connectivity()
    dsc = DownstreamClient()
    if args.:
         dsc.get_challenges()
         dsc.answer_challenge()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('node')
    parser.add_argument('--answer-challenge', action='store_true')


def main():
    args = parse_args()
    eval_args(args)

if __name__ == '__main__':
    main()
