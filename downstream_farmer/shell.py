#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import os
import sys
import argparse
import json
import signal

from .client import DownstreamClient
from .version import __version__
from .exc import DownstreamError

#from six.moves.urllib.request import urlopen
#from six.moves.urllib.error import URLError
import six


def fail_exit(msg, exit_code=1):
    sys.stderr.write('Error: %s\n' % msg)
    sys.exit(exit_code)


def handler(signum=None, frame=None):
    sys.exit(0)


class Farmer(object):

    def __init__(self, args):
        """The farmer should have some priorities on how it uses the
        parameters.

        1) if a url is not specified, it loads saved url and connects to that
           node
        2) if no node is specified on disk,  connect to our prototype node.
        3) if no token is specified, it attempts to load the token for the node
           from disk
        4) if no token is on disk, it will attempt to retrieve a new farming
           token from the node.  this requires an address.
        5) if no address is specified on the command line, it will attempt to
           load the address for the node from disk
        6) if no address is available, fail.
        7) if an address is given on the command line that is different from
           the saved address, it uses the specified address and obtains a new
           token

        :returns: a dictionary with the arguments
        """
        if args.number is not None and args.number < 1:
            raise DownstreamError(
                'Must specify a positive number of challenges.')

        self.number = args.number

        if args.size < 1:
            raise DownstreamError('Must specify a positive size to farm.')

        self.size = args.size

        self.path = args.path

        self.restore()

        # resolve url
        if (args.node_url is not None):
            url = args.node_url
        else:
            url = self.state.get('last_url',
                                 'http://verify.driveshare.org:8000')

        self.url = url.strip('/')
        print('Using url {0}'.format(self.url))

        self.check_connectivity()

        self.state['last_url'] = self.url

        if (args.token is not None):
            self.token = args.token
        else:
            self.token = self.state.get('nodes', dict()).\
                get(self.url, dict()).get('token', None)

        saved_address = self.state.get('nodes', dict()).\
            get(self.url, dict()).get('address', None)

        if (args.address is not None):
            self.address = args.address
            if (saved_address is not None and self.address != saved_address):
                print('New address specified, obtaining new token.')
                self.token = None
        else:
            self.address = saved_address

        if (self.token is None and self.address is None):
            raise DownstreamError(
                'Must specify farming address if one is not available.')

        if (self.token is not None):
            print('Using token {0}'.format(self.token))

        if (self.address is not None):
            print('Farming on address {0}'.format(self.address))

    def save(self):
        """saves the farmer state to disk
        """
        (head, tail) = os.path.split(self.path)
        if (len(head) > 0 and not os.path.isdir(head)):
            os.mkdir(head)
        with open(self.path, 'w+') as f:
            json.dump(self.state, f)

    def restore(self):
        """restores state from disk
        """
        if (os.path.exists(self.path)):
            with open(self.path, 'r') as f:
                self.state = json.load(f)
        else:
            self.state = dict()

    def check_connectivity(self):
        """ Check to see if we even get a connection to the server.
        https://stackoverflow.com/questions/3764291/checking-network-connection
        """
        try:
            six.moves.urllib.request.urlopen(self.url, timeout=2)
        except six.moves.urllib.error.URLError:
            raise DownstreamError("Could not connect to server.")

    def run(self):
        client = DownstreamClient(
            self.url, self.token, self.address, self.size)

        client.connect()

        # connection successful, save our state, then begin farming
        self.state.setdefault('nodes', dict())[client.server] = {
            'token': client.token,
            'address': client.address
        }

        self.save()

        client.run(self.number)


def eval_args(args):
    try:
        farmer = Farmer(args)

        farmer.run()

    except DownstreamError as e:
        fail_exit('Error: {0}'.format(str(e)))
    except Exception as e:
        fail_exit('Unexpected error: {0}'.format(str(e)))
    except:
        fail_exit('Unknown error.')


def parse_args():
    parser = argparse.ArgumentParser('downstream-farmer')
    parser.add_argument('-V', '--version', action='version',
                        version=__version__)
    parser.add_argument('node_url', nargs='?',
                        help='URL of the Downstream node')
    parser.add_argument('-n', '--number', type=int,
                        help='Number of challenges to perform.'
                        'If unspecified, perform challenges until killed.')
    parser.add_argument('-p', '--path',
                        default=os.path.join('data', 'state'),
                        help='Path to save/load state from.')
    parser.add_argument('-s', '--size', type=int, default=100,
                        help='Total size of contracts to obtain.')
    parser.add_argument('-a', '--address', help='SJCX address')
    parser.add_argument('-t', '--token', help='Farming token')
    return parser.parse_args()


def main():
    for sig in [signal.SIGTERM, signal.SIGINT]:
        signal.signal(sig, handler)

    args = parse_args()
    eval_args(args)
