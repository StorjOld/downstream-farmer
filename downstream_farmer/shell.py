#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import sys
import argparse

from .client import DownstreamClient
from downstream_farmer import __version__
from downstream_farmer.exc import ConnectError, DownstreamError

try:
    from urllib2 import urlopen, URLError
except ImportError:
    from urllib.request import urlopen
    from urllib.error import URLError


def fail_exit(msg, exit_code=1):
    sys.stderr.write('Error: %s\n' % msg)
    sys.exit(exit_code)


def verify_ownership(client, filename):
    print('Fetching challenges...')
    try:
        client.get_challenges(filename)
    except DownstreamError as e:
        fail_exit(e.message)

    print('Verifying ownership...')
    try:
        response = client.answer_challenge(filename)
    except DownstreamError as e:
        fail_exit(e.message)

    match = response['match']
    if match:
        print('\nFILE MATCHED!')
    else:
        print('\nFailed to match.')


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

    dsc = DownstreamClient(args.node_url)

    if args.verify_ownership:
        verify_ownership(dsc, args.verify_ownership)


def parse_args():
    parser = argparse.ArgumentParser('downstream-farmer')
    parser.add_argument('-V', '--version', action='version',
                        version=__version__)
    parser.add_argument('node_url', help='URL of the Downstream node')
    parser.add_argument(
        '--verify-ownership',
        nargs='?',
        metavar='/path/to/file',
        help='Verify ownership of a file to a Downstream node'
    )
    return parser.parse_args()


def main():
    args = parse_args()
    eval_args(args)

if __name__ == '__main__':
    main()
