#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse

from .client import DownstreamClient


def eval_args(args):
    dsc = DownstreamClient()
    if args.gen_challenge:
         dsc.get_challenges()
         dsc.answer_challenge()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--answer-challenge', action='store_true',
                        help='')


def main():
    args = parse_args()
    eval_args(args)

if __name__ == '__main__':
    main()