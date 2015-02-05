#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import os
import sys
import argparse
import logging
import traceback

from .version import __version__
from .exc import DownstreamError
from .farmer import Farmer

logger = logging.getLogger('storj.downstream_farmer')


class SmartFormatter(argparse.HelpFormatter):

    """From http://stackoverflow.com/questions/3853722/python-argparse-how-to-insert-newline-in-the-help-text  # NOQA
    """

    def _split_lines(self, text, width):
        # this is the RawTextHelpFormatter._split_lines
        if text.startswith('R|'):
            return text[2:].splitlines()
        return argparse.HelpFormatter._split_lines(self, text, width)


def fail_exit(msg, exit_code=1):
    logger.info(msg)
    sys.exit(exit_code)


def eval_args(args):
    try:
        farmer = Farmer(args)

        farmer.run(True)

    except DownstreamError as e:
        logger.error(traceback.format_exc())
        fail_exit('Error: {0}'.format(str(e)))
    except:
        logger.error(traceback.format_exc())
        fail_exit('Unexpected error: {0}'.format(sys.exc_info()[1]))


def parse_args(args=None):
    history_path = os.path.join('data', 'history.json')
    identity_path = os.path.join('data', 'identities.json')
    chunk_path = os.path.join('data', 'chunks')
    default_size = 33554432  # 32 MiB
    default_url = 'https://live.driveshare.org:8443'
    log_path = 'farmer.log'
    parser = argparse.ArgumentParser(
        'downstream', formatter_class=SmartFormatter)
    parser.add_argument('-V', '--version', action='version',
                        version=__version__)
    parser.add_argument('node_url', nargs='?',
                        help='URL of the downstream node to connect to. '
                        'The default node is {0}'.format(default_url))
    parser.add_argument('-n', '--number', type=int,
                        help='Number of challenges to perform. '
                        'If unspecified, perform challenges until killed.')
    parser.add_argument('-p', '--history', default=history_path,
                        help='Path to save/load history from. The history file'
                        ' saves your farming tokens for each node you connect '
                        'to.  The default path is {0}.'.format(history_path))
    parser.add_argument('-s', '--size', type=int, default=default_size,
                        help='Total size of contracts to obtain in bytes. '
                        'Default is {0} bytes'.format(default_size))
    parser.add_argument('-a', '--address', help='SJCX address for farming. You'
                        ' can specify this if you have multiple identities and'
                        ' would like to farm under one of them.  Otherwise by '
                        'default, an address from your identity file ({0}) '
                        'will be used.'.format(identity_path))
    parser.add_argument('-t', '--token', help='Farming token to use.  If you '
                        'already have a farming token, you can reconnect to '
                        'the node with it by specifying it here.  By default '
                        'a new token will be obtained.  Any tokens obtained '
                        'will be saved in the history JSON file.')
    parser.add_argument('-f', '--forcenew', help='Force obtaining a new token.'
                        ' If the node has been reset and your token has been '
                        'deleted, it may be necessary to force your farmer to '
                        'obtain a new token.',
                        action='store_true')
    parser.add_argument('-i', '--identity', default=identity_path,
                        help='R|Specify an identity file to  provide a '
                        'signature to\nprove ownership of your SJCX address. '
                        'The default path\nis {0}.  The file format should be '
                        'a\nJSON dictionary like the following:\n'
                        '{{\n'
                        '   "your sjcx address": {{\n'
                        '      "message": "your message here",\n'
                        '      "signature": "base64 signature from bitcoin\\\n'
                        '                     wallet or counterwallet",\n'
                        '   }}\n'
                        '}}\n'
                        'If an identity is specified in this file, it will '
                        'be\nused for connecting to any new nodes.'
                        .format(identity_path))
    parser.add_argument('-d', '--data-directory', default=chunk_path,
                        help='Data directory to place file chunks.  By default'
                        ' {0}'.format(chunk_path))
    parser.add_argument('--ssl-no-verify', help='Do not verify ssl '
                        'certificates.', action='store_true')
    parser.add_argument('--log-path', help='Path to the log file.  Default is:'
                        ' {0}'.format(log_path),
                        default=log_path)
    parser.add_argument('--quiet', help='Do not show the status console.',
                        action='store_true')
    parser.add_argument('--print-log', help='Print log to screen instead of '
                        'status console.', action='store_true')
    return parser.parse_args(args)


def main(cmargs=None):
    args = parse_args(cmargs)
    eval_args(args)
