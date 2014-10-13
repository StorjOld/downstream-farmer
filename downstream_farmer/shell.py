#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import os
import sys
import argparse
import base58

from .client import DownstreamClient
from downstream_farmer.version import __version__
from downstream_farmer.exc import ConnectError, DownstreamError

try:
    from urllib2 import urlopen, URLError
except ImportError:
    from urllib.request import urlopen
    from urllib.error import URLError


def fail_exit(msg, exit_code=1):
    sys.stderr.write('Error: %s\n' % msg)
    sys.exit(exit_code)


def run_prototype(url, number):
    try:
        # generate a blank address...
        test_address = base58.b58encode_check(b'\x00'+os.urandom(20))
        client = DownstreamClient(test_address)

        print('Connect to server')
        client.connect(url)

        print('Fetching contract')
        client.get_chunk()

        print('Answering challenge 0')
        client.answer_challenge()

        i = 1
        while number == 0 or i < number:
            print('Answering challenge {0}'.format(i+1))
            client.get_challenge()
            client.answer_challenge()
            i += 1

        print('Verification successful!')

    except DownstreamError as e:
        fail_exit(e.message)


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
        check_connectivity(args.node_url)
    except ConnectError as e:
        fail_exit(e.message)

    if args.number < 0:
        fail_exit('Must specify a non-negative number of challenges.')

    run_prototype(args.node_url, args.number)


def parse_args():
    parser = argparse.ArgumentParser('downstream-farmer')
    parser.add_argument('-V', '--version', action='version',
                        version=__version__)
    parser.add_argument('node_url', help='URL of the Downstream node')
    parser.add_argument('-n', '--number', type=int,
                        default=0,
                        help='Number of challenges to perform.  '
                        'If unspecified, perform challenges until killed.')
    return parser.parse_args()


def main():
    args = parse_args()
    eval_args(args)
