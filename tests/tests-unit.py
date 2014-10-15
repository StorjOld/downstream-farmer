#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import unittest
import base58
import binascii
from argparse import Namespace

from six.moves.urllib.error import URLError

import mock
import requests
from datetime import datetime, timedelta

from downstream_farmer import utils, shell
from downstream_farmer.client import DownstreamClient, Contract
from downstream_farmer.exc import DownstreamError, Py3kException, ConnectError
from heartbeat import Heartbeat


class TestUtils(unittest.TestCase):
    def test_urlify(self):
        test_str = "arbitrary strings 'n shit"
        result = utils.urlify(test_str)
        self.assertEqual('arbitrary%20strings%20%27n%20shit', result)

    def test_handle_json_response(self):
        m = mock.MagicMock()
        m.raise_for_status.side_effect = Exception("Test")
        with self.assertRaises(DownstreamError) as ex:
            utils.handle_json_response(m)
        
        m = mock.MagicMock()
        m.json.side_effect = ValueError
        with self.assertRaises(DownstreamError) as ex:
            utils.handle_json_response(m)
        
        m = mock.MagicMock()
        result = utils.handle_json_response(m)

class TestContract(unittest.TestCase):
    def setUp(self):
        self.challenge = Heartbeat.challenge_type()()
        self.tag = Heartbeat.tag_type()()
        self.expiration = datetime.utcnow()+timedelta(seconds=60)
        self.contract = Contract('hash',
                                 'seed',
                                 12345,
                                 self.challenge,
                                 self.expiration,
                                 self.tag)
    
    def tearDown(self):
        pass
    
    def test_initialization(self):
        self.assertEqual(self.contract.hash,'hash')
        self.assertEqual(self.contract.seed,'seed')
        self.assertEqual(self.contract.size,12345)
        self.assertEqual(self.contract.challenge,self.challenge)
        self.assertEqual(self.contract.expiration,self.expiration)
        self.assertEqual(self.contract.tag,self.tag)
        
class TestClient(unittest.TestCase):
    def setUp(self):
        self.server_url = 'https://test.url/'
        self.address = base58.b58encode_check(b'\x00'+os.urandom(20))
        self.client = DownstreamClient(self.address)
        self.test_contract = Contract(MockValues.get_chunk_response['file_hash'],
                                      MockValues.get_chunk_response['seed'],
                                      MockValues.get_chunk_response['size'],
                                      Heartbeat.challenge_type().fromdict(
                                        MockValues.get_chunk_response['challenge']),
                                      datetime.strptime(
                                        MockValues.get_chunk_response['expiration'],
                                        '%Y-%m-%dT%H:%M:%S'),
                                      Heartbeat.tag_type().fromdict(
                                        MockValues.get_chunk_response['tag']))
        self.test_heartbeat = Heartbeat.fromdict(MockValues.connect_response['heartbeat'])

    def tearDown(self):
        pass

    def test_initialization(self):
        self.assertEqual(self.client.address, self.address)
        self.assertEqual(len(self.client.token),0)
        self.assertEqual(len(self.client.server),0)
        self.assertIsNone(self.client.heartbeat)
        self.assertIsNone(self.client.contract)

    def test_connect_malformed(self):
        with mock.patch('downstream_farmer.client.requests.get') as patch:
            inst = patch.return_value
            inst.json.return_value = {"invalid":"dict"}
            with self.assertRaises(DownstreamError) as ex:
                self.client.connect(self.server_url)
            self.assertEqual(str(ex.exception),'Malformed response from server.')
    
    def test_connect_invalid_heartbeat(self):
        with mock.patch('downstream_farmer.client.requests.get') as patch:
            inst = patch.return_value
            inst.json.return_value = {"heartbeat":"test heartbeat",
                                      "token":"test token",
                                      "type":"invalid type"}
            with self.assertRaises(DownstreamError) as ex:
                self.client.connect(self.server_url)
            self.assertEqual(str(ex.exception),'Unknown Heartbeat Type')

    def test_connect_working(self):
        with mock.patch('downstream_farmer.client.requests.get') as patch:
            inst = patch.return_value
            inst.json.return_value = MockValues.connect_response
            self.client.connect(self.server_url)
        self.assertEqual(self.client.token,MockValues.connect_response['token'])
        self.assertEqual(self.client.heartbeat,
                         Heartbeat.fromdict(MockValues.connect_response['heartbeat']))

    def test_get_chunk_malformed(self):
        with mock.patch('downstream_farmer.client.requests.get') as patch:
            inst = patch.return_value
            inst.json.return_value = {"invalid":"dict"}
            with self.assertRaises(DownstreamError) as ex:
                self.client.get_chunk()
            self.assertEqual(str(ex.exception),'Malformed response from server.')

    def test_get_chunk_working(self):
        self.client.heartbeat = self.test_heartbeat
        with mock.patch('downstream_farmer.client.requests.get') as patch:
            inst = patch.return_value
            inst.json.return_value = MockValues.get_chunk_response
            self.client.get_chunk()
        self.assertEqual(self.client.contract.hash, self.test_contract.hash)
        self.assertEqual(self.client.contract.seed, self.test_contract.seed)
        self.assertEqual(self.client.contract.size, self.test_contract.size)
        self.assertEqual(self.client.contract.challenge, self.test_contract.challenge)
        self.assertEqual(self.client.contract.expiration, self.test_contract.expiration)
        self.assertEqual(self.client.contract.tag, self.test_contract.tag)

    def test_challenge_no_contract(self):
        self.client.contract = None
        with self.assertRaises(DownstreamError) as ex:
            self.client.get_challenge()
        self.assertEqual(str(ex.exception),'No contract to get a new challenge for.')

    def test_challenge_malformed(self):
        self.client.contract = self.test_contract
        self.client.heartbeat = self.test_heartbeat
        with mock.patch('downstream_farmer.client.requests.get') as patch:
            inst = patch.return_value
            inst.json.return_value = {"invalid":"dict"}
            with self.assertRaises(DownstreamError) as ex:
                self.client.get_challenge()
            self.assertEqual(str(ex.exception),'Malformed response from server.')
    
    def test_challenge_block_til_expired(self):
        self.client.contract = self.test_contract
        self.client.heartbeat = self.test_heartbeat
        self.client.contract.expiration = datetime.utcnow()+timedelta(seconds=3)
        with mock.patch('downstream_farmer.client.requests.get') as patch:
            inst = patch.return_value
            inst.json.return_value = MockValues.get_challenge_response
            self.assertIsNotNone(self.client.get_challenge())
            
    def test_challenge_no_block(self):
        self.client.contract = self.test_contract
        self.client.heartbeat = self.test_heartbeat
        self.client.contract.expiration = datetime.utcnow()+timedelta(seconds=3)
        with mock.patch('downstream_farmer.client.requests.get') as patch:
            inst = patch.return_value
            inst.json.return_value = MockValues.get_challenge_response
            self.assertIsNone(self.client.get_challenge(block=False))

    def test_challenge_working(self):
        self.client.contract = self.test_contract
        self.client.heartbeat = self.test_heartbeat
        with mock.patch('downstream_farmer.client.requests.get') as patch:
            inst = patch.return_value
            inst.json.return_value = MockValues.get_challenge_response
            self.client.get_challenge()
            self.assertEqual(self.client.contract.challenge, 
                             Heartbeat.challenge_type().fromdict(
                                MockValues.get_challenge_response['challenge']))
            self.assertEqual(self.client.contract.expiration,
                             datetime.strptime(
                                MockValues.get_challenge_response['expiration'],
                                '%Y-%m-%dT%H:%M:%S'))
            
    def test_answer_no_contract(self):
        self.client.contract = None
        with self.assertRaises(DownstreamError) as ex:
            self.client.answer_challenge()
        self.assertEqual(str(ex.exception),'No contract to answer.')
        
    def test_answer_malformed(self):
        self.client.contract = self.test_contract
        self.client.heartbeat = self.test_heartbeat
        with mock.patch('downstream_farmer.client.requests.post') as patch:
            inst = patch.return_value
            inst.json.return_value = {"invalid":"dict"}
            with self.assertRaises(DownstreamError) as ex:
                self.client.answer_challenge()
            self.assertEqual(str(ex.exception),'Malformed response from server.')
    
    def test_answer_invalid(self):
        self.client.contract = self.test_contract
        self.client.heartbeat = self.test_heartbeat
        with mock.patch('downstream_farmer.client.requests.post') as patch:
            inst = patch.return_value
            inst.json.return_value = {"status":"dict"}
            with self.assertRaises(DownstreamError) as ex:
                self.client.answer_challenge()
            self.assertEqual(str(ex.exception),'Challenge response rejected.')
            
    def test_answer_working(self):
        self.client.contract = self.test_contract
        self.client.heartbeat = self.test_heartbeat
        with mock.patch('downstream_farmer.client.requests.post') as patch:
            inst = patch.return_value
            inst.json.return_value = {"status":"ok"}
            self.client.answer_challenge()
    
class TestExceptions(unittest.TestCase):
    def test_py3kexception(self):
        e = Py3kException('Test Exception')
        self.assertEqual(e.message, 'Test Exception')
        result = str(e)
        self.assertEqual(result, 'Test Exception')

    def test_downstream_error(self):
        e = DownstreamError('Test Exception')
        self.assertEqual(e.message, 'Test Exception')
        result = str(e)
        self.assertEqual(result, 'Test Exception')

    def test_connecterror(self):
        e = ConnectError('Test Exception')
        self.assertEqual(e.message, 'Test Exception')
        result = str(e)
        self.assertEqual(result, 'Test Exception')


class TestShell(unittest.TestCase):
    def setUp(self):
        self._old_argv = sys.argv

    def tearDown(self):
        sys.argv = self._old_argv

    def test_parse_args(self):
        sys.argv = [
            'downstream', 'http://localhost:5000'
        ]
        args = shell.parse_args()
        self.assertIsInstance(args, Namespace)

        with self.assertRaises(SystemExit):
            sys.argv[1] = '--version'
            shell.parse_args()

    def test_eval_args(self):
        with mock.patch('downstream_farmer.shell.check_connectivity') as check:
            check.side_effect = ConnectError('Oops')
            m = mock.Mock()
            with self.assertRaises(SystemExit):
                shell.eval_args(m)
            self.assertTrue(check.called)

        with mock.patch('downstream_farmer.shell.check_connectivity'):
            m.number = -1
            with self.assertRaises(SystemExit):
                shell.eval_args(m)
            with mock.patch('downstream_farmer.shell.run_prototype') as rp:
                m.number = 2
                shell.eval_args(m)
                self.assertTrue(rp.called)

    def test_run_prototype(self):
        m = mock.Mock()
        with mock.patch('downstream_farmer.shell.DownstreamClient') as dc:
            inst = dc.return_value
            inst.connect.side_effect = DownstreamError('Error')
            with self.assertRaises(SystemExit):
                shell.run_prototype(m,1)
            
        with mock.patch('downstream_farmer.shell.DownstreamClient') as dc:
            shell.run_prototype(m,2)
            inst = dc.return_value
            self.assertTrue(dc.called)
            self.assertTrue(inst.connect.called)
            self.assertTrue(inst.get_chunk.called)
            self.assertTrue(inst.answer_challenge.called)
            self.assertTrue(inst.get_challenge.called)
                    
    def test_check_connectivity(self):
        with mock.patch('downstream_farmer.shell.urlopen') as patch:
            patch.side_effect = URLError('Problem')
            with self.assertRaises(ConnectError) as ex:
                shell.check_connectivity(None)

        with mock.patch('downstream_farmer.shell.urlopen'):
            result = shell.check_connectivity(None)
            self.assertIsNone(result)
            
    def test_main(self):
        with mock.patch('downstream_farmer.shell.parse_args') as pa:
            with mock.patch('downstream_farmer.shell.eval_args') as ea:
                shell.main()
                self.assertTrue(pa.called)
                self.assertTrue(ea.called)
                
    def test_fail_exit(self):
        with self.assertRaises(SystemExit):
            shell.fail_exit('Test')


class MockValues:
    connect_response = {
        "heartbeat": "AQoAAACAAAAAgAAAAJCTCchnuw8nE9FbjUyJVNNzjQumBHHw7iFL5Ply"
                     "4vHQvkqOqcgc5XKXgWVaJGCs1F+oI68zL9Ir9+q0BkA5WadDq5uz0Cot"
                     "sY8Pad8UemCLvLGNlnkavsbn0dXk7/0QL5KYGardu9m5zWtQEagdvl86"
                     "tSbksec1B5Y9K1S5hGlr",
        "token": "b45a3e2932c87474cb1bd7e642cf792b",
        "type": "SwPriv"
    }

    get_chunk_response = {
        "challenge": "AQAAACAAAACJwjEuYPkbnGOppNVgG0Xc5GKgp0g2kGN2bMCssbMBwIAA"
                     "AACQkwnIZ7sPJxPRW41MiVTTc40LpgRx8O4hS+T5cuLx0L5KjqnIHOVy"
                     "l4FlWiRgrNRfqCOvMy/SK/fqtAZAOVmnQ6ubs9AqLbGPD2nfFHpgi7yx"
                     "jZZ5Gr7G59HV5O/9EC+SmBmq3bvZuc1rUBGoHb5fOrUm5LHnNQeWPStU"
                     "uYRpaw==",
        "expiration": "2014-10-06T11:49:57",
        "file_hash": "89ca8e5f02e64694bf889d49a9b7986f201900e6637e0e7349282a85"
                     "91ce7732",
        "seed": "eb1bb0f7cd24720d456193cca8c42edb",
        "size": 100,
        "tag": "AQAAAIAAAABqXU8BK1mOXFG0mK+X1lWNZ39AmYe1M4JsbIz36wC0PvvcWY+URw"
               "+BYBlFk5N1+X5VI4F+3sDYYy0jE7mgVCh7kNnOZ/mAYtffFh7izOOS4HHuzWIm"
               "cOgaVeBL0/ngSPLPYUhFF5uTzKoYUr+SheQDYcuOCg8qivXZGOL6Hv1WVQ=="
    }
    
    get_challenge_response = {
        "challenge": "AQAAACAAAAAs/0pRrQ00cWS86II/eAufStyqrjf0wSJ941EjtrLo94AA"
                     "AABSnAK49Tm7F/4HkQuvdJj1WdisL9OEuMMl9uYMxIp8aXvDqkI/NP4r"
                     "ix6rREa1Jh6pvH6Mb4DpVHEjDMzVIOKEKV8USKndUq2aNiYf2NqQ1Iw0"
                     "XkNFsoSgZD10miN8YtatUNu+8gUkT6cv54DUrruo9JTIpXsIqu0BNifu"
                     "FU58Vw==",
        "expiration": "2014-10-09T14:57:11"
    }