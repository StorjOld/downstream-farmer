#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import unittest
from argparse import Namespace
try:
    from urllib2 import URLError
except ImportError:
    from urllib.error import URLError

import mock
import requests

from downstream_farmer import utils, shell
from downstream_farmer.client import DownstreamClient
from downstream_farmer.exc import DownstreamError, Py3kException, ConnectError


class TestUtils(unittest.TestCase):
    def test_urlify(self):
        test_str = "arbitrary strings 'n shit"
        result = utils.urlify(test_str)
        self.assertEqual('arbitrary%20strings%20%27n%20shit', result)


class TestClient(unittest.TestCase):
    def setUp(self):
        self.server_url = 'https://test.url/'
        self.client = DownstreamClient(self.server_url)
        self.testfile = 'tests/thirty-two_meg.testfile'

    def tearDown(self):
        pass

    def test_initialization(self):
        self.assertEqual(self.client.server, self.server_url[:-1])
        self.assertEqual(self.client.challenges, [])
        self.assertIsNone(self.client.heartbeat)

    def test_connect(self):
        with self.assertRaises(NotImplementedError):
            self.client.connect(None)

    def test_store_path(self):
        with self.assertRaises(NotImplementedError):
            self.client.store_path(None)

    def test_get_chunk(self):
        with self.assertRaises(NotImplementedError):
            self.client.get_chunk(None)

    def test_challenge(self):
        with self.assertRaises(NotImplementedError):
            self.client.challenge(None, None)

    def test_answer(self):
        with self.assertRaises(NotImplementedError):
            self.client.answer(None, None)

    def test_enc_fname(self):
        test_file = '/path/to/my test.file'
        result = self.client._enc_fname(test_file)
        self.assertEqual('my%20test.file', result)

    @mock.patch('downstream_farmer.client.requests')
    def test_get_challenges_server(self, requests):
        inst = requests.get.return_value
        inst.raise_for_status.side_effect = Exception('Test')
        with self.assertRaises(DownstreamError) as ex:
            self.client.get_challenges(self.testfile)
        self.assertEqual(ex.exception.message, 'Error connecting to downstream-node: Test')

    @mock.patch('downstream_farmer.client.requests')
    def test_get_challenges_json(self, requests):
        inst = requests.get.return_value
        inst.json.side_effect = ValueError
        with self.assertRaises(DownstreamError) as ex:
            self.client.get_challenges(self.testfile)
        self.assertEqual(ex.exception.message, 'Invalid response from Downstream node.')

    def test_get_challenges_working(self):
        with mock.patch('downstream_farmer.client.requests.get') as patch:
            inst = patch.return_value
            inst.json.return_value = MockValues.response
            self.client.get_challenges(self.testfile)
        self.assertEqual(len(MockValues.response['challenges']),
                         len(self.client.challenges))

    def test_answer_challenge(self):
        with mock.patch('downstream_farmer.client.os.path.isfile') as patch:
            patch.side_effect = AssertionError
            with self.assertRaises(DownstreamError) as ex:
                self.client.answer_challenge(self.testfile)
        msg = ex.exception.message
        self.assertEqual(msg, 'tests/thirty-two_meg.testfile is not a valid file')

        with mock.patch('downstream_farmer.client.requests.get') as patch:
            inst = patch.return_value
            inst.json.return_value = MockValues.response
            self.client.get_challenges(self.testfile)
        self.assertEqual(len(MockValues.response['challenges']),
                         len(self.client.challenges))

        with mock.patch('downstream_farmer.client.requests.post') as patch:
            resp = patch.return_value
            resp.json.side_effect = ValueError
            result = self.client.answer_challenge(self.testfile)
            self.assertEqual(result, {})

        with mock.patch('downstream_farmer.client.requests.post') as patch:
            resp = patch.return_value
            resp.json.return_value = {'msg': 'epic fail'}
            resp.status_code = 400
            resp.raise_for_status.side_effect = requests.exceptions.HTTPError
            with self.assertRaises(DownstreamError) as ex:
                self.client.answer_challenge(self.testfile)
            msg = ex.exception.message
            self.assertEqual(
                msg, 'Error reponse from Downstream node: 400 epic fail')

        with mock.patch('downstream_farmer.client.requests.post') as patch:
            resp = patch.return_value
            resp.json.return_value = MockValues.challenge_answer
            result = self.client.answer_challenge(self.testfile)
            self.assertEqual(result, MockValues.challenge_answer)

    def test_random_challenge(self):
        with mock.patch('downstream_farmer.client.requests.get') as patch:
            inst = patch.return_value
            inst.json.return_value = MockValues.response
            self.client.get_challenges(self.testfile)
        result = self.client.random_challenge()
        self.assertIn(result, self.client.challenges)


class MockValues:
    response = {
        "challenges": [
            {
                "block": 3117129,
                "filename": "thirty-two_meg.testfile",
                "rootseed":
                    "d10d510e1ff1f61ad8aa051fca3bbdbd93f8b6534cf04beadfc52c6229a621bd",
                "seed":
                    "767bbdd1ea1174b1d6ec0168d27f1d167a28def3ed985773f78915e28f44086c"
            },
            {
                "block": 33325195,
                "filename": "thirty-two_meg.testfile",
                "rootseed":
                    "d10d510e1ff1f61ad8aa051fca3bbdbd93f8b6534cf04beadfc52c6229a621bd",
                "seed":
                    "2bd3debc7bcea5c907a5e507abcd5e2a225c8aa1b6699c7861e3763657fc75f8"
            },
            {
                "block": 2012152,
                "filename": "thirty-two_meg.testfile",
                "rootseed":
                    "d10d510e1ff1f61ad8aa051fca3bbdbd93f8b6534cf04beadfc52c6229a621bd",
                "seed":
                    "75406dd8f6246553dd0685373a2e25e090fbf8d4a6f853aceea08d0d717a57fa"
            },
            {
                "block": 18367663,
                "filename": "thirty-two_meg.testfile",
                "rootseed":
                    "d10d510e1ff1f61ad8aa051fca3bbdbd93f8b6534cf04beadfc52c6229a621bd",
                "seed":
                    "77629c499da7dd50c9a96ae34137510a294ba286657fc7e954844e14f98cbdfb"
            },
            {
                "block": 28897911,
                "filename": "thirty-two_meg.testfile",
                "rootseed":
                    "d10d510e1ff1f61ad8aa051fca3bbdbd93f8b6534cf04beadfc52c6229a621bd",
                "seed":
                    "8c1098d75f9f4768b231acf6a358c7e096b2bb7f629f1131113c7ecf9df2e21e"
            },
            {
                "block": 5726630,
                "filename": "thirty-two_meg.testfile",
                "rootseed":
                    "d10d510e1ff1f61ad8aa051fca3bbdbd93f8b6534cf04beadfc52c6229a621bd",
                "seed":
                    "a2b691a3897db1656432f39caaccab72d64c16e3976543b3953cf251a370d6c8"
            },
            {
                "block": 25814394,
                "filename": "thirty-two_meg.testfile",
                "rootseed":
                    "d10d510e1ff1f61ad8aa051fca3bbdbd93f8b6534cf04beadfc52c6229a621bd",
                "seed":
                    "7ae97605df3ba0994bef0dd4ec929ceed7e6bf66a2a25109ce4d0a97a4d83d52"
            },
            {
                "block": 26668230,
                "filename": "thirty-two_meg.testfile",
                "rootseed":
                    "d10d510e1ff1f61ad8aa051fca3bbdbd93f8b6534cf04beadfc52c6229a621bd",
                "seed":
                    "96ba083338cc902b04d8c11ef641eea0f12604c5953e3b2f7f0644869e713221"
            },
            {
                "block": 4829621,
                "filename": "thirty-two_meg.testfile",
                "rootseed":
                    "d10d510e1ff1f61ad8aa051fca3bbdbd93f8b6534cf04beadfc52c6229a621bd",
                "seed":
                    "ccfef476a18df028f3e978efc788d4d7c2c088c7c91cc376679d1799fe9a1bb0"
            },
        ]
    }

    challenge_answer = {
        'msg': 'ok',
        'match': True
    }