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

        saved_token = self.state.get('nodes', dict()).\
            get(self.url, dict()).get('token', None)

        if (args.token is not None):
            self.token = args.token
        else:
            self.token = saved_token

        if (args.forcenew):
            if (self.token is not None):
                print('Not using token {0} since '
                      'forcenew was specified.'.format(self.token))
                self.token = None

        saved_address = self.state.get('nodes', dict()).\
            get(self.url, dict()).get('address', None)

        if (args.address is not None):
            self.address = args.address
            if (self.address != saved_address):
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
    default_path = os.path.join('data', 'state.json')
    default_size = 100
    parser = argparse.ArgumentParser('downstream')
    parser.add_argument('-V', '--version', action='version',
                        version=__version__)
    parser.add_argument('node_url', nargs='?',
                        help='URL of the downstream node to connect to')
    parser.add_argument('-n', '--number', type=int,
                        help='Number of challenges to perform. '
                        'If unspecified, perform challenges until killed.')
    parser.add_argument('-p', '--path',
                        default=default_path,
                        help='Path to save/load state from.  The state file '
                        'saves your last connected node, your farming tokens, '
                        'your SJCX address, and other data.  The default is '
                        '{0}'.format(default_path))
    parser.add_argument('-s', '--size', type=int, default=default_size,
                        help='Total size of contracts to obtain in bytes. '
                        'Default is {0} bytes'.format(default_size))
    parser.add_argument('-a', '--address', help='SJCX address for farming. You'
                        ' only need to specify this the first time you connect'
                        ' after that, your address is saved by the node under '
                        'your farming token')
    parser.add_argument('-t', '--token', help='Farming token to use.  If you '
                        'already have a farming token, you can reconnect to '
                        'the node with it by specifying it here.  By default '
                        'a new token will be obtained if you specify an SJCX '
                        'address to use.')
    parser.add_argument('-f', '--forcenew', help='Force obtaining a new token.'
                        ' If the node has been reset and your token has been '
                        'deleted, it may be necessary to force your farmer to '
                        'obtain a new token.',
                        action='store_true')
    return parser.parse_args()


def main():
    for sig in [signal.SIGTERM, signal.SIGINT]:
        signal.signal(sig, handler)

    args = parse_args()
    eval_args(args)
