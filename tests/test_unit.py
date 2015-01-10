#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import unittest
import base58
import binascii
from argparse import Namespace, HelpFormatter
import json
import RandomIO
import threading
import signal

from six.moves.urllib.error import URLError

import mock
from datetime import datetime, timedelta

from downstream_farmer import utils, shell
from downstream_farmer.utils import save, restore
from downstream_farmer.utils import ManagedThread, ThreadManager, ShellApplication
from downstream_farmer.utils import WorkChunk, LoadTracker
from downstream_farmer.farmer import Farmer
from downstream_farmer.client import DownstreamClient, ContractPool
from downstream_farmer.contract import DownstreamContract
from downstream_farmer.exc import DownstreamError
from heartbeat import Heartbeat


class TestUtilFunctions(unittest.TestCase):

    def test_urlify(self):
        test_str = "arbitrary strings 'n shit"
        result = utils.urlify(test_str)
        self.assertEqual('arbitrary%20strings%20%27n%20shit', result)

    def test_handle_json_response(self):
        m = mock.MagicMock()
        m.status_code = 400
        m.json.return_value = dict(message='test error')
        with self.assertRaises(DownstreamError) as ex:
            utils.handle_json_response(m)
        self.assertEqual(str(ex.exception), 'test error')

        m.json.side_effect = Exception('json processing error')
        m.raise_for_status.side_effect = Exception('http error')
        with self.assertRaises(Exception) as ex:
            utils.handle_json_response(m)
        self.assertEqual(str(ex.exception), 'http error')

        m = mock.MagicMock()
        m.json.return_value = dict(key='value')
        result = utils.handle_json_response(m)
        self.assertEqual(m.json.return_value, result)
    
    def test_resource_path_meipass(self):
        test_dir = 'testdir'
        test_file = 'testfile'
        setattr(sys, '_MEIPASS', test_dir)
        self.assertEqual(utils.resource_path(test_file),os.path.join(test_dir, test_file))
        delattr(sys, '_MEIPASS')
    
    def test_resource_path_default(self):
        test_file = 'testfile'
        default_path = os.path.join(
            os.path.join(os.path.dirname(utils.__file__), 'data'),
            test_file)
        self.assertEqual(utils.resource_path(test_file), default_path)
    
    def test_save_restore_parity(self):
        d = {'key': 'value'}
        path = 'test_file'
        save(path, d)
        r = restore(path)
        self.assertEqual(d, r)
        os.remove(path)

    def test_restore_path_doesnt_exist(self):
        path = 'nonexistentpath'
        state = restore(path)
        self.assertEqual(state, dict())

    def test_save_directory_creation(self):
        d = {'key': 'value'}
        dir = 'testdir'
        path = os.path.join(dir, 'file')
        save(path, d)
        self.assertTrue(os.path.isdir(dir))
        self.assertTrue(os.path.exists(path))
        r = restore(path)
        self.assertEqual(d, r)
        os.remove(path)
        os.rmdir(dir)

    def test_restore_parse_fail(self):
        path = 'test_file'
        with open(path, 'w') as f:
            f.write('test contents')
        with mock.patch('json.loads') as l:
            l.side_effect = Exception('test error')
            with self.assertRaises(DownstreamError) as ex:
                restore(path)
            self.assertEqual(
                str(ex.exception), 'Couldn\'t parse \'{0}\': test error'
                .format(path))
        os.remove(path)

    
class TestManagedThread(unittest.TestCase):
    def setUp(self):
        def mock_target():
            threading.current_thread().wait()
    
        self.thread = ManagedThread(target=mock_target)
    
    def tearDown(self):
        pass
    
    def test_init(self):
        self.assertTrue(self.thread.daemon)
        self.assertFalse(self.thread.attached_event.is_set())
        
    def test_wake(self):
        self.thread.start()
        self.assertTrue(self.thread.is_alive())
        self.thread.wake()
        self.assertTrue(self.thread.attached_event.is_set())
        self.thread.join()
        self.assertFalse(self.thread.is_alive())
        

class TestThreadManager(unittest.TestCase):
    def setUp(self):
        self.thread_manager = ThreadManager()
    
    def tearDown(self):
        self.thread_manager.finish()
        
    def test_init(self):
        self.assertTrue(self.thread_manager.running)
        self.thread_manager.finish()
        self.assertFalse(self.thread_manager.running)
     
    def test_start_thread(self):
        def mock_target(manager):
            manager.sleep(10)
        
        thread = self.thread_manager.create_thread(target=mock_target, args=(self.thread_manager,))
        thread.start()
        self.assertTrue(thread.is_alive())
        self.thread_manager.finish()
        self.assertFalse(thread.is_alive())
        
    def test_wait_for_shutdown(self):
        class MockTargetGenerator(object):
            def __init__(self, manager):
                self.manager = manager
                
            def __call__(self, arg=None):
                self.manager.signal_shutdown()
                raise InterruptedError('test error')

        with mock.patch('downstream_farmer.utils.time.sleep') as s:
            s.side_effect = MockTargetGenerator(self.thread_manager)
            self.thread_manager.wait_for_shutdown()
        self.assertFalse(self.thread_manager.running)

class TestShellApplication(unittest.TestCase):
    def setUp(self):
        self.shell_app = ShellApplication()
    
    def test_init(self):
        self.assertTrue(self.shell_app.running)
    
    def test_signal_handler(self):
        self.shell_app.signal_handler()
        self.assertFalse(self.shell_app.running)

class TestWorkChunk(unittest.TestCase):
    def setUp(self):
        self.chunk = WorkChunk(0,2)
        
    def test_elapsed(self):
        self.assertEqual(self.chunk.elapsed, 2)
    
    def test_elapsed_from_start_shortened(self):
        self.assertEqual(self.chunk.elapsed_from_start(1), 1)
    
    def test_elapsed_from_start_default(self):
        self.assertEqual(self.chunk.elapsed_from_start(0), 2)
    

class TestLoadTracker(unittest.TestCase):
    def setUp(self):
        self.start_time = 0
        self.sample_time = 10
        with mock.patch('downstream_farmer.utils.time.time') as t:
            t.return_value = self.start_time
            self.tracker = LoadTracker(self.sample_time)
    
    def test_init(self):
        self.assertEqual(self.start_time, self.tracker.start)
    
    def test_sample_start_full(self):
        now = 20        
        with mock.patch('downstream_farmer.utils.time.time') as t:
            t.return_value = now
            sample_start = self.tracker.sample_start
        self.assertEqual(sample_start, now - self.sample_time)
        
    def test_sample_start_partial(self):
        now = 5
        with mock.patch('downstream_farmer.utils.time.time') as t:
            t.return_value = now
            sample_start = self.tracker.sample_start
        self.assertEqual(sample_start, self.start_time)
    
    def test_normal_chunks(self):
        with mock.patch('downstream_farmer.utils.time.time') as t:
            # add a couple of work chunks
            t.return_value = 20
            self.tracker.start_work()
            t.return_value = 21
            self.tracker.finish_work()
            t.return_value = 22
            self.tracker.start_work()
            t.return_value = 23
            self.tracker.finish_work()
            self.assertEqual(self.tracker.work_time(), 2)
            self.assertAlmostEqual(self.tracker.load(), 2/self.sample_time)
    
    def test_early_chunks(self):
        with mock.patch('downstream_farmer.utils.time.time') as t:
            t.return_value = 1
            self.tracker.start_work()
            t.return_value = 2
            self.tracker.finish_work()
            self.assertEqual(self.tracker.work_time(), 1)
            self.assertAlmostEqual(self.tracker.load(), 1/t.return_value)
    
    def test_finish_before_start(self):
        with self.assertRaises(RuntimeError) as ex:
            self.tracker.finish_work()
        self.assertEqual(str(ex.exception), 'Load tracker work chunk must be started before'
                                   ' it can be finished.')
                                   
    def test_chunk_expiry(self):
        with mock.patch('downstream_farmer.utils.time.time') as t:
            t.return_value = 5
            self.tracker.start_work()
            t.return_value = 10
            self.tracker.finish_work()
            t.return_value = 15
            self.tracker.start_work()
            t.return_value = 20
            self.tracker.finish_work()
            t.return_value = 25
            self.tracker.start_work()
            t.return_value = 29
            self.tracker.finish_work()
            self.assertEqual(self.tracker.work_time(), 5)
            self.assertAlmostEqual(self.tracker.load(), 0.5)
            
    def test_unfinished_work(self):
        with mock.patch('downstream_farmer.utils.time.time') as t:
            t.return_value = 5
            self.tracker.start_work()
            t.return_value = 10
            self.assertEqual(self.tracker.work_time(), 5)
            self.assertAlmostEqual(self.tracker.load(), 0.5)
    
class MockRestore(object):

    def __init__(self, table):
        self.table = table

    def __call__(self, arg):
        return self.table[arg]


class MockRaiseOnFirstCall(object):

    def __init__(self, error):
        self.called = False
        self.error = error

    def __call__(self, arg=None):
        if (not self.called):
            self.called = True
            raise self.error

class TestFarmer(unittest.TestCase):
    def setUp(self):
        self.test_args = mock.MagicMock()
        self.test_args.number = None
        self.test_args.node_url = 'http://testurl/'
        self.test_args.api_path = '/api/downstream/v1'
        self.test_args.token = 'testtoken'
        self.test_args.address = 'testaddress'
        self.test_args.size = 100
        self.test_args.history = 'historyfile'
        self.test_args.forcenew = False
        self.test_args.identity = 'identityfile'
        self.test_args.data_directory = os.path.join('data','chunks')
    
    def tearDown(self):
        pass

    def test_init_number_invalid(self):
        self.test_args.number = -1
        with self.assertRaises(DownstreamError) as ex:
            Farmer(self.test_args)
        self.assertEqual(
            str(ex.exception), 'Must specify a positive number of challenges.')

    def test_init_size_invalid(self):
        self.test_args.size = 0
        with self.assertRaises(DownstreamError) as ex:
            Farmer(self.test_args)
        self.assertEqual(
            str(ex.exception), 'Must specify a positive size to farm.')

    def test_init_forcenew(self):
        self.test_args.forcenew = True
        with mock.patch('downstream_farmer.utils.restore', autospec=True) as r,\
                mock.patch.object(Farmer, 'check_connectivity'):
            r.side_effect = MockRestore(
                {'historyfile': dict(), 'identityfile': dict()})
            farmer = Farmer(self.test_args)
        self.assertIsNone(farmer.token)

    def test_init_no_token_no_address(self):
        self.test_args.token = None
        self.test_args.address = None
        with mock.patch('downstream_farmer.utils.restore', autospec=True) as r,\
                mock.patch.object(Farmer, 'check_connectivity'),\
                self.assertRaises(DownstreamError) as ex:
            r.side_effect = MockRestore(
                {'historyfile': dict(), 'identityfile': dict()})
            Farmer(self.test_args)
        self.assertEqual(
            str(ex.exception),
            'Must specify farming address if one is not available.')

    def test_init_url(self):
        self.test_args.node_url = 'testurl'
        with mock.patch('downstream_farmer.utils.restore', autospec=True) as r,\
                mock.patch.object(Farmer, 'check_connectivity'):
            r.side_effect = MockRestore(
                {'historyfile': dict(), 'identityfile': dict()})
            farmer = Farmer(self.test_args)
            self.assertEqual(farmer.url, self.test_args.node_url)
            self.assertEqual(
                farmer.state['last_node'], self.test_args.node_url)

    def test_init_url_from_state(self):
        self.test_args.node_url = None
        with mock.patch('downstream_farmer.farmer.restore', autospec=True) as r,\
                mock.patch.object(Farmer, 'check_connectivity'):
            r.side_effect = MockRestore(
                {'historyfile': {'last_node': 'stateurl'},
                 'identityfile': dict()})
            farmer = Farmer(self.test_args)
            self.assertEqual(farmer.url, 'stateurl')

    def test_init_url_default(self):
        self.test_args.node_url = None
        with mock.patch('downstream_farmer.farmer.restore', autospec=True) as r,\
                mock.patch.object(Farmer, 'check_connectivity'):
            r.side_effect = MockRestore(
                {'historyfile': dict(), 'identityfile': dict()})
            farmer = Farmer(self.test_args)
            self.assertEqual(farmer.url, 'https://live.driveshare.org:8443')

    def test_init_token(self):
        self.test_args.address = None
        with mock.patch('downstream_farmer.farmer.restore', autospec=True) as r,\
                mock.patch.object(Farmer, 'check_connectivity'):
            r.side_effect = MockRestore(
                {'historyfile': dict(), 'identityfile': dict()})
            farmer = Farmer(self.test_args)
            self.assertEqual(farmer.token, self.test_args.token)

    def test_init_token_from_state(self):
        self.test_args.token = None
        with mock.patch('downstream_farmer.farmer.restore', autospec=True) as r,\
                mock.patch.object(Farmer, 'check_connectivity'):
            r.side_effect = MockRestore({
                'historyfile': {
                    'nodes': {
                        self.test_args.node_url.strip('/'): {
                            'token': 'statetoken',
                            'address': 'testaddress'
                        }
                    }
                },
                'identityfile': dict()})
            farmer = Farmer(self.test_args)
            self.assertEqual(farmer.token, 'statetoken')

    def test_init_token_default(self):
        self.test_args.token = None
        with mock.patch('downstream_farmer.farmer.restore', autospec=True) as r,\
                mock.patch.object(Farmer, 'check_connectivity'):
            r.side_effect = MockRestore(
                {'historyfile': dict(), 'identityfile': dict()})
            farmer = Farmer(self.test_args)
            self.assertEqual(farmer.token, None)

    def test_init_address(self):
        with mock.patch('downstream_farmer.farmer.restore', autospec=True) as r,\
                mock.patch.object(Farmer, 'check_connectivity'):
            r.side_effect = MockRestore(
                {'historyfile': dict(), 'identityfile': dict()})
            farmer = Farmer(self.test_args)
            self.assertEqual(farmer.address, self.test_args.address)

    def test_init_address_from_state(self):
        self.test_args.address = None
        with mock.patch('downstream_farmer.farmer.restore', autospec=True) as r,\
                mock.patch.object(Farmer, 'check_connectivity'):
            r.side_effect = MockRestore({'historyfile': {
                'nodes': {
                    self.test_args.node_url.strip('/'): {
                        'token': 'statetoken',
                        'address': 'stateaddress'
                    }
                }
            }, 'identityfile': dict()})
            farmer = Farmer(self.test_args)
            self.assertEqual(farmer.address, 'stateaddress')

    def test_init_address_default(self):
        self.test_args.address = None
        with mock.patch('downstream_farmer.farmer.restore', autospec=True) as r,\
                mock.patch.object(Farmer, 'check_connectivity'):
            r.side_effect = MockRestore(
                {'historyfile': dict(), 'identityfile': dict()})
            farmer = Farmer(self.test_args)
            self.assertEqual(farmer.address, None)

    def test_init_address_from_identities(self):
        self.test_args.address = None
        with mock.patch('downstream_farmer.farmer.restore', autospec=True) as r,\
                mock.patch.object(Farmer, 'check_connectivity'):
            r.side_effect = MockRestore({'historyfile': dict(),
                                         'identityfile':
                                         {'19qVgG8C6eXwKMMyvVegsi3xCsKyk3Z3jV':
                                          {'signature': 'HyzVUenXXo4pa+kgm1v'
                                           'S8PNJM83eIXFC5r0q86FGbqFcdla6rcw'
                                           '72/ciXiEPfjli3ENfwWuESHhv6K9esI0'
                                           'dl5I=', 'message':
                                           'test message'}}})
            farmer = Farmer(self.test_args)
            self.assertEqual(
                farmer.address, '19qVgG8C6eXwKMMyvVegsi3xCsKyk3Z3jV')

    def test_load_signature_invalid_dict(self):
        self.test_args.token = None
        self.test_args.address = None
        with mock.patch('downstream_farmer.farmer.restore', autospec=True) as r,\
                mock.patch.object(Farmer, 'check_connectivity'):
            r.side_effect = MockRestore({'historyfile': dict(),
                                         'identityfile':
                                         {'identityaddress': {'invalid':
                                                              'dict'}}})
            with self.assertRaises(DownstreamError) as ex:
                Farmer(self.test_args)
            self.assertEqual(str(ex.exception),
                             'The file format for the identity file '
                             '{0} should be a JSON formatted dictionary like '
                             'the following:\n'
                             '   {{\n'
                             '      "your sjcx address": {{\n'
                             '         "message": "your message here",\n'
                             '         "signature":  "base64 signature from '
                             'bitcoin wallet or counterwallet",\n'
                             '      }}\n'
                             '   }}'.format(self.test_args.identity))

    def test_load_signature_invalid_sig(self):
        self.test_args.token = None
        self.test_args.address = None
        with mock.patch('downstream_farmer.farmer.restore', autospec=True) as r,\
                mock.patch.object(Farmer, 'check_connectivity'),\
                mock.patch('siggy.verify_signature') as s:
            s.return_value = False
            r.side_effect = MockRestore({'historyfile': dict(),
                                         'identityfile':
                                         {'identityaddress':
                                          {'signature': 'testsig', 'message':
                                           'testmessage'}}})
            with self.assertRaises(DownstreamError) as ex:
                Farmer(self.test_args)
            self.assertEqual(str(ex.exception), 'Signature provided does not'
                             ' match address being used. '
                             'Check your formatting, your SJCX address, and'
                             ' try again.')

    def test_load_signature_none(self):
        with mock.patch('downstream_farmer.farmer.restore', autospec=True) as r,\
                mock.patch.object(Farmer, 'check_connectivity'):
            r.side_effect = MockRestore({'historyfile': dict(),
                                         'identityfile':
                                         {'identityaddress':
                                          {'signature': 'testsig', 'message':
                                           'testmessage'}}})
            farmer = Farmer(self.test_args)
            self.assertEqual(farmer.message, '')
            self.assertEqual(farmer.signature, '')

    def test_check_connectivity(self):
        with mock.patch('downstream_farmer.farmer.restore', autospec=True) as r,\
                mock.patch('six.moves.urllib.request.urlopen') as patch:
            r.side_effect = MockRestore(
                {'historyfile': dict(), 'identityfile': dict()})
            farmer = Farmer(self.test_args)
            patch.side_effect = URLError('Problem')
            with self.assertRaises(DownstreamError):
                farmer.check_connectivity()

        with mock.patch('six.moves.urllib.request.urlopen') as patch:
            farmer.check_connectivity()
            self.assertTrue(patch.called)

    def test_run(self):
        with mock.patch('downstream_farmer.farmer.restore', autospec=True) as r,\
                mock.patch('six.moves.urllib.request.urlopen') as patch:
            r.side_effect = MockRestore(
                {'historyfile': dict(), 'identityfile': dict()})
            farmer = Farmer(self.test_args)
        with mock.patch('downstream_farmer.farmer.DownstreamClient') as patch,\
                mock.patch('downstream_farmer.farmer.save', autospec=True) as s,\
                mock.patch.object(Farmer, 'wait_for_shutdown') as w:
            patch.return_value.token = 'foo'
            patch.return_value.address = 'bar'
            farmer.run(True)
            patch.assert_called_with(
                farmer.url, farmer.token, farmer.address, farmer.size, '', '', farmer, farmer.chunk_dir)
            patch.return_value.run_async.assert_called_with(True, farmer.number)
            self.assertTrue(w.called)
            self.assertTrue(patch.return_value.connect.called)
            self.assertEqual(farmer
                             .state['nodes'][patch.return_value
                                             .server]['token'],
                             patch.return_value.token)
            self.assertEqual(farmer
                             .state['nodes'][patch.return_value
                                             .server]['address'],
                             patch.return_value.address)
            self.assertTrue(s.called)
            
    def test_run_nonexistent_token_reconnect(self):
        with mock.patch('downstream_farmer.farmer.restore', autospec=True) as r,\
                mock.patch('six.moves.urllib.request.urlopen') as patch:
            r.side_effect = MockRestore(
                {'historyfile': dict(), 'identityfile': dict()})
            farmer = Farmer(self.test_args)
        with mock.patch('downstream_farmer.farmer.DownstreamClient') as patch,\
                mock.patch('downstream_farmer.farmer.save', autospec=True) as s,\
                mock.patch.object(Farmer, 'wait_for_shutdown') as w:
            patch.return_value.connect.side_effect = \
                MockRaiseOnFirstCall(DownstreamError('Unable to connect: Nonexistent token.'))
            farmer.run(True)
            self.assertEqual(patch.return_value.connect.call_count, 2)
    
    def test_run_unable_to_connect(self):
        with mock.patch('downstream_farmer.farmer.restore', autospec=True) as r,\
                mock.patch('six.moves.urllib.request.urlopen') as patch:
            r.side_effect = MockRestore(
                {'historyfile': dict(), 'identityfile': dict()})
            farmer = Farmer(self.test_args)
        with mock.patch('downstream_farmer.farmer.DownstreamClient') as patch:
            patch.return_value.connect.side_effect = DownstreamError('test error')
            with self.assertRaises(DownstreamError) as ex:
                farmer.run(True)
            self.assertEqual(str(ex.exception), 'test error')
     
    def test_prepare_chunk_dir(self):
        with mock.patch('downstream_farmer.farmer.restore', autospec=True) as r,\
                mock.patch('six.moves.urllib.request.urlopen') as patch,\
                mock.patch('downstream_farmer.farmer.os') as os_patch:
            r.side_effect = MockRestore(
                {'historyfile': dict(), 'identityfile': dict()})
            os_patch.path.isdir.return_value = False            
            farmer = Farmer(self.test_args)
            os_patch.mkdir.assert_called_with(farmer.chunk_dir)
    
    def test_prepare_chunk_fail(self):
        with mock.patch('downstream_farmer.farmer.restore', autospec=True) as r,\
                mock.patch('six.moves.urllib.request.urlopen') as patch,\
                mock.patch('downstream_farmer.farmer.os') as os_patch:
            r.side_effect = MockRestore(
                {'historyfile': dict(), 'identityfile': dict()})
            os_patch.path.isdir.return_value = False
            os_patch.mkdir.side_effect = RuntimeError('test exception')
            with self.assertRaises(DownstreamError) as ex:
                farmer = Farmer(self.test_args)
            self.assertEqual(
                str(ex.exception), 
                'Chunk directory could not be created: test exception')
    

class TestContract(unittest.TestCase):

    def setUp(self):
        self.challenge = Heartbeat.challenge_type().\
            fromdict(MockValues.get_challenge_response['challenge'])
        self.heartbeat = Heartbeat.fromdict(
            MockValues.connect_response['heartbeat'])
        self.tag = Heartbeat.tag_type().fromdict(
            MockValues.get_chunk_response['tag'])
        self.expiration = datetime.utcnow(
        ) + timedelta(int(MockValues.get_chunk_response['due']))
        self.client = mock.MagicMock()
        self.manager = ThreadManager()
        self.test_hash = 'hash'
        self.test_size = 100
        self.test_seed = 'seed'
        self.contract = DownstreamContract(self.client,
                                           self.test_hash,
                                           self.test_seed,
                                           self.test_size,
                                           self.challenge,
                                           self.expiration,
                                           self.tag,
                                           self.manager,
                                           os.path.join('data','chunks'))
        self.contract.generate_data()

    def tearDown(self):
        self.contract.cleanup_data()

    def test_initialization(self):
        self.assertEqual(self.contract.client, self.client)
        self.assertEqual(self.contract.hash, self.test_hash)
        self.assertEqual(self.contract.seed, self.test_seed)
        self.assertEqual(self.contract.size, self.test_size)
        self.assertEqual(self.contract.challenge, self.challenge)
        self.assertEqual(self.contract.expiration, self.expiration)
        self.assertEqual(self.contract.tag, self.tag)
        self.assertEqual(self.contract.answered, False)
        self.assertEqual(self.contract.path, os.path.join('data','chunks',self.test_hash))

    def test_repr(self):
        self.assertEqual(str(self.contract), self.contract.hash)
    
    def test_with(self):
        with self.contract:
            self.assertTrue(os.path.isfile(self.contract.path))
        self.assertFalse(os.path.exists(self.contract.path))
        
    def test_time_remaining(self):
        self.assertLessEqual(self.contract.time_remaining(), 0)

        with mock.patch('downstream_farmer.contract.datetime') as patch:
            patch.utcnow.return_value = datetime.utcnow()
            self.contract.answered = True
            dt = self.contract.expiration - patch.utcnow.return_value
            result = self.contract.time_remaining()
        self.assertEqual(result, dt.total_seconds())

    def test_update_challenge_answered(self):
        # answered is false, so this should return immediately with no issues
        self.assertIsNone(self.contract.update_challenge())

    def test_update_challenge_block(self):
        self.contract.answered = True
        self.contract.time_remaining = mock.MagicMock()
        self.contract.time_remaining.return_value = 1
        self.contract.thread_manager = mock.MagicMock()
        with mock.patch(
                    'downstream_farmer.contract.requests.get') as getpatch:
            getpatch.return_value.json.return_value =\
                MockValues.get_challenge_response
            self.contract.update_challenge()
            self.assertTrue(self.contract.thread_manager.sleep.called)
            
    def test_update_challenge_exit_after_sleep(self):
        self.contract.answered = True
        self.contract.thread_manager = mock.MagicMock()
        self.contract.time_remaining = mock.MagicMock()
        self.contract.time_remaining.return_value = 1
        self.contract.thread_manager.running = False
        with mock.patch('downstream_farmer.contract.requests.get') as getpatch:
            self.contract.update_challenge()
        self.contract.thread_manager.sleep.assert_called_with(1)
        self.assertFalse(getpatch.called)

    def test_update_challenge_no_block(self):
        self.contract.answered = True
        self.contract.time_remaining = mock.MagicMock()
        self.contract.time_remaining.return_value = 1
        with mock.patch('time.sleep') as sleeppatch,\
                mock.patch(
                    'downstream_farmer.contract.requests.get') as getpatch:
            getpatch.return_value.json.return_value =\
                MockValues.get_challenge_response
            self.contract.update_challenge(block=False)
            self.assertFalse(sleeppatch.called)

    def test_update_challenge_get_fail(self):
        self.contract.answered = True
        self.contract.time_remaining = mock.MagicMock()
        self.contract.time_remaining.return_value = 0
        with mock.patch('downstream_farmer.contract.requests.get') as getpatch:
            getpatch.side_effect = Exception('error')
            with self.assertRaises(DownstreamError) as ex:
                self.contract.update_challenge()
            self.assertEqual(str(ex.exception), 'Unable to perform HTTP get.')

    def test_update_challenge_failed(self):
        self.contract.answered = True
        self.contract.time_remaining = mock.MagicMock()
        self.contract.time_remaining.return_value = 0
        with mock.patch(
                'downstream_farmer.contract.requests.get'),\
                mock.patch('downstream_farmer.contract.handle_json_response')\
                as hpatch:
            hpatch.side_effect = DownstreamError('error')
            with self.assertRaises(DownstreamError) as ex:
                self.contract.update_challenge()
            self.assertEqual(str(ex.exception), 'Challenge update failed.')
            
    def test_update_challenge_no_more_challenges(self):
        self.contract.answered = True
        self.contract.time_remaining = mock.MagicMock()
        self.contract.time_remaining.return_value = 0
        with mock.patch(
            'downstream_farmer.contract.requests.get'),\
                mock.patch('downstream_farmer.contract.handle_json_response')\
                as hpatch:
            hpatch.return_value = dict(status='no more challenges')
            with self.assertRaises(DownstreamError) as ex:
                self.contract.update_challenge()
            self.assertEqual(str(ex.exception), 'No more challenges for contract {0}'.format(self.contract.hash))

    def test_update_challenge_malformed(self):
        self.contract.answered = True
        self.contract.time_remaining = mock.MagicMock()
        self.contract.time_remaining.return_value = 0
        with mock.patch('downstream_farmer.contract.requests.get'),\
                mock.patch('downstream_farmer.contract.handle_json_response')\
                as hpatch:
            hpatch.return_value = dict(invalid='dict')
            with self.assertRaises(DownstreamError) as ex:
                self.contract.update_challenge()
            self.assertEqual(
                str(ex.exception), 'Malformed response from server.')

    def test_update_challenge_working(self):
        self.contract.answered = True
        self.client.heartbeat = self.heartbeat
        self.contract.time_remaining = mock.MagicMock()
        self.contract.time_remaining.return_value = 0
        with mock.patch('downstream_farmer.contract.requests.get') as getpatch:
            getpatch.return_value.json.return_value =\
                MockValues.get_challenge_response
            self.contract.update_challenge()
            self.assertEqual(self.contract.challenge,
                             Heartbeat.challenge_type().fromdict(
                                 MockValues
                                 .get_challenge_response['challenge']))
            self.assertAlmostEqual((self.
                                    contract.expiration - datetime.utcnow()).
                                   total_seconds(),
                                   int(MockValues.
                                       get_challenge_response['due']),
                                   delta=0.5)

    def test_answer_challenge_answered(self):
        self.contract.answered = True
        self.assertIsNone(self.contract.answer_challenge())

    def test_answer_challenge_post_fail(self):
        self.client.heartbeat = self.heartbeat
        with mock.patch('downstream_farmer.contract.requests.post') as ppatch:
            ppatch.side_effect = Exception('test error')
            with self.assertRaises(DownstreamError) as ex:
                self.contract.answer_challenge()
            self.assertEqual(str(ex.exception), 'Unable to perform HTTP post.')

    def test_answer_challenge_failed(self):
        self.client.heartbeat = self.heartbeat
        with mock.patch('downstream_farmer.contract.requests.post'),\
                mock.patch('downstream_farmer.contract.handle_json_response')\
                as hpatch:
            hpatch.side_effect = DownstreamError('test error')
            with self.assertRaises(DownstreamError) as ex:
                self.contract.answer_challenge()
            self.assertEqual(
                str(ex.exception), 'Challenge answer failed: test error')

    def test_answer_malformed(self):
        self.client.heartbeat = self.heartbeat
        with mock.patch('downstream_farmer.contract.requests.post') as patch:
            inst = patch.return_value
            inst.json.return_value = {"invalid": "dict"}
            with self.assertRaises(DownstreamError) as ex:
                self.contract.answer_challenge()
            self.assertEqual(
                str(ex.exception), 'Malformed response from server.')

    def test_answer_invalid(self):
        self.client.heartbeat = self.heartbeat
        with mock.patch('downstream_farmer.contract.requests.post') as patch:
            inst = patch.return_value
            inst.json.return_value = {"status": "dict"}
            with self.assertRaises(DownstreamError) as ex:
                self.contract.answer_challenge()
            self.assertEqual(str(ex.exception), 'Challenge response rejected.')

    def test_answer_working(self):
        self.client.heartbeat = self.heartbeat
        with mock.patch('downstream_farmer.contract.requests.post') as patch:
            inst = patch.return_value
            inst.json.return_value = {"status": "ok"}
            self.contract.answer_challenge()
            self.assertTrue(self.contract.answered)

class MockContractShutdown(object):
    def __init__(self, manager):
        self.manager = manager
    
    def __call__(self, arg=None):
        self.manager.running = False

class MockShutdownAndRaise(MockContractShutdown):
    def __init__(self, manager, exc):
        MockContractShutdown.__init__(self, manager)
        self.exception = exc

    def __call__(self, arg=None):
        MockContractShutdown.__call__(self)
        raise self.exception

class TestContractPool(unittest.TestCase):
    def setUp(self):
        self.manager = ThreadManager()
        self.contract_thread = ManagedThread()
        self.contract_pool = ContractPool(self.manager,
                                          self.contract_thread)
    
    def tearDown(self):
        del self.contract_pool
        
    def test_init(self):
        self.assertEqual(len(self.contract_pool.contracts), 0)
    
    def test_repr(self):
        self.assertEqual(str(self.contract_pool), self.contract_pool.id)
        
    def test_start(self):
        self.contract_pool.thread = mock.MagicMock()
        self.contract_pool.start()
        self.assertTrue(self.contract_pool.thread.start.called)
    
    def add_test_contracts(self):
        self.contract1 = mock.MagicMock()
        self.contract1.size = 100
        self.contract1.time_remaining.return_value = 10
        self.contract2 = mock.MagicMock()
        self.contract2.size = 200
        self.contract2.time_remaining.return_value = 20
        self.contract_pool.add_contract(self.contract1)
        self.contract_pool.add_contract(self.contract2)
    
    def test_get_total_size(self):
        self.add_test_contracts()
        self.assertEqual(self.contract_pool.get_total_size(), 300)
    
    def test_get_total_size_zero(self):
        self.assertEqual(self.contract_pool.get_total_size(), 0)
    
    def test_contract_count(self):
        self.add_test_contracts()
        self.assertEqual(self.contract_pool.contract_count(), 2)
    
    def test_get_average_load(self):
        self.contract_pool.load_tracker = mock.MagicMock()
        self.assertEqual(self.contract_pool.get_average_load(),
                         self.contract_pool.load_tracker.load.return_value)
        
    def test_remove_contract(self):
        self.add_test_contracts()
        self.assertEqual(self.contract_pool.contract_count(), 2)
        self.contract_pool.remove_contract(self.contract1)
        self.assertEqual(self.contract_pool.contract_count(), 1)
        self.assertTrue(self.contract1.cleanup_data.called)
    
    def test_remove_all_contracts(self):
        self.add_test_contracts()
        self.contract_pool.remove_all_contracts()
        self.assertEqual(self.contract_pool.contract_count(), 0)
        self.assertTrue(self.contract1.cleanup_data.called)
        self.assertTrue(self.contract2.cleanup_data.called)
     
    def test_get_next_contract(self):
        self.add_test_contracts()
        self.assertEqual(self.contract_pool.get_next_contract(),
                         self.contract1)
    
    def add_due_contract(self):
        self.contract0 = mock.MagicMock()
        self.contract0.size = 100
        self.contract0.time_remaining.return_value = 0
        self.contract_pool.add_contract(self.contract0)
        
    def mock_thread_manager(self):
        self.contract_pool.thread_manager = mock.MagicMock()
        self.contract_pool.thread_manager.running = True
    
    def test_run_challenge_response_loop(self):
        self.add_due_contract()
        self.contract_pool.wake_ct_on_hb = True
        self.mock_thread_manager()
        self.contract_pool.contract_thread = mock.MagicMock()
        
        self.contract_pool.contract_thread.wake.side_effect = \
            MockContractShutdown(self.contract_pool.thread_manager)
            
        self.contract_pool._run_challenge_response_loop()
        
        self.contract0.update_challenge.assert_called_with(False)
        self.assertTrue(self.contract0.answer_challenge.called)
        
    def test_run_challenge_response_loop_no_contracts_wait(self):
        self.mock_thread_manager()
        
        self.contract_pool.thread = mock.MagicMock()

        self.contract_pool.thread.wait.side_effect = \
            MockContractShutdown(self.contract_pool.thread_manager)
            
        self.contract_pool._run_challenge_response_loop()
        
        self.assertTrue(self.contract_pool.thread.wait.called)
    
    def test_run_challenge_response_loop_update_failed(self):
        self.add_due_contract()
        self.mock_thread_manager()
        
        self.contract0.update_challenge.side_effect = \
            MockShutdownAndRaise(self.contract_pool.thread_manager,
                                 DownstreamError('test error'))
        
        self.contract_pool._run_challenge_response_loop()
        
        # contract should have been removed
        
        self.assertEqual(self.contract_pool.contract_count(), 0)
        
    def test_run_challenge_response_loop_answer_failed(self):
        self.add_due_contract()
        self.mock_thread_manager()
        
        self.contract0.answer_challenge.side_effect = \
            MockShutdownAndRaise(self.contract_pool.thread_manager,
                                 DownstreamError('test error'))
        
        self.contract_pool._run_challenge_response_loop()
        
        # contract should have been removed
        
        self.assertEqual(self.contract_pool.contract_count(), 0)
    
    
class AddContractMock(object):
    def __init__(self, client, manager_to_shutdown=None):
        self.client = client
        self.manager = manager_to_shutdown
    
    def __call__(self, contract, wake_on_hb):
        self.client.get_total_size.return_value += contract.size
        if (self.manager is not None):
            self.manager.running = False
    
    
class TestClient(unittest.TestCase):

    def setUp(self):
        self.server_url = 'https://test.url/'
        self.api_path = '/api/downstream/v1'
        self.size = 100
        self.address = base58.b58encode_check(b'\x00' + os.urandom(20))
        self.token = binascii.hexlify(os.urandom(16)).decode('ascii')
        self.msg = ''
        self.sig = ''
        self.thread_manager = ThreadManager()
        self.contract_thread = ManagedThread()
        self.chunk_dir = os.path.join('data','chunks')
        self.client = DownstreamClient(self.server_url,
                                       self.token,
                                       self.address,
                                       self.size,
                                       self.msg,
                                       self.sig,
                                       self.thread_manager,
                                       self.chunk_dir)
        self.test_contract = \
            DownstreamContract(self.client,
                               MockValues.get_chunk_response['file_hash'],
                               MockValues.get_chunk_response['seed'],
                               MockValues.get_chunk_response['size'],
                               Heartbeat.challenge_type().fromdict(
                                   MockValues.get_chunk_response['challenge']),
                               datetime.utcnow() + timedelta(
                                   seconds=int(
                                       MockValues.get_chunk_response['due'])),
                               Heartbeat.tag_type().fromdict(
                                   MockValues.get_chunk_response['tag']),
                               self.thread_manager,
                               self.chunk_dir)
        self.test_heartbeat = Heartbeat.fromdict(
            MockValues.connect_response['heartbeat'])
        self.test_contract_pool = ContractPool(self.thread_manager,
                                               self.contract_thread)
        self.test_contract_pool.add_contract(self.test_contract)

    def tearDown(self):
        pass

    def test_initialization(self):
        self.assertEqual(self.client.server, self.server_url.strip('/'))
        self.assertEqual(self.client.address, self.address)
        self.assertEqual(self.client.token, self.token)
        self.assertEqual(self.client.desired_size, self.size)
        self.assertIsNone(self.client.heartbeat)
        self.assertEqual(len(self.client.contract_pools), 0)

    def test_connect_no_token_no_address(self):
        self.client.address = None
        self.client.token = None
        with self.assertRaises(DownstreamError) as ex:
            self.client.connect()
        self.assertEqual(
            str(ex.exception), 'If no token is specified, address must be.')

    def test_connect_failed(self):
        with mock.patch('downstream_farmer.client.requests.get'),\
                mock.patch('downstream_farmer.client.handle_json_response')\
                as hp:
            hp.side_effect = DownstreamError('test error')
            with self.assertRaises(DownstreamError) as ex:
                self.client.connect()
            self.assertEqual(
                str(ex.exception), 'Unable to connect: test error')

    def test_connect_malformed(self):
        with mock.patch('downstream_farmer.client.requests.get') as patch:
            inst = patch.return_value
            inst.json.return_value = {"invalid": "dict"}
            with self.assertRaises(DownstreamError) as ex:
                self.client.connect()
            self.assertEqual(
                str(ex.exception), 'Malformed response from server.')

    def test_connect_invalid_heartbeat(self):
        with mock.patch('downstream_farmer.client.requests.get') as patch:
            inst = patch.return_value
            inst.json.return_value = {"heartbeat": "test heartbeat",
                                      "token": "test token",
                                      "type": "invalid type"}
            with self.assertRaises(DownstreamError) as ex:
                self.client.connect()
            self.assertEqual(str(ex.exception), 'Unknown Heartbeat Type')

    def test_connect_working_new(self):
        self.client.token = None
        with mock.patch('downstream_farmer.client.requests.get') as patch:
            patch.return_value.json.return_value = MockValues.connect_response
            self.client.connect()
        patch.assert_called_with(
            '{0}/new/{1}'.format(self.server_url.strip('/') + self.api_path,
                                 self.address), verify=None)
        self.assertEqual(
            self.client.token, MockValues.connect_response['token'])
        self.assertEqual(self.client.heartbeat,
                         Heartbeat
                         .fromdict(MockValues.connect_response['heartbeat']))

    def test_connect_working(self):
        with mock.patch('downstream_farmer.client.requests.get') as patch:
            patch.return_value.json.return_value = MockValues.connect_response
            self.client.connect()
        patch.assert_called_with('{0}/heartbeat/{1}'.format(
            self.server_url.strip('/') + self.api_path, self.token),
            verify=None)
        self.assertEqual(
            self.client.token, MockValues.connect_response['token'])
        self.assertEqual(self.client.heartbeat,
                         Heartbeat
                         .fromdict(MockValues.connect_response['heartbeat']))

    def test_connect_sign(self):
        self.client.msg = 'test message'
        self.client.sig = 'HyzVUenXXo4pa+kgm1vS8PNJM83eIXFC5r0q86FGbqFcdla6rcw'
        '72/ciXiEPfjli3ENfwWuESHhv6K9esI0dl5I='
        self.client.address = '19qVgG8C6eXwKMMyvVegsi3xCsKyk3Z3jV'
        self.client.token = None
        with mock.patch('downstream_farmer.client.requests.post') as patch:
            patch.return_value.json.return_value = MockValues.connect_response
            self.client.connect()
        patch.assert_called_with('{0}/new/{1}'.format(self.server_url
                                                      .strip('/') + self
                                                      .api_path, self
                                                      .client.address),
                                 data=json.dumps({
                                     "message": self.client.msg,
                                     "signature": self.client.sig
                                 }),
                                 headers={
            'Content-Type': 'application/json'
        },
            verify=None)
        self.assertEqual(
            self.client.token, MockValues.connect_response['token'])
        self.assertEqual(self.client.heartbeat,
                         Heartbeat.fromdict(MockValues
                                            .connect_response['heartbeat']))

    def test_get_contract_no_token(self):
        with mock.patch('downstream_farmer.client.requests.get'),\
                mock.patch('downstream_farmer.client.handle_json_response')\
                as hp:
            hp.side_effect = DownstreamError('test error')
            with self.assertRaises(DownstreamError) as ex:
                self.client.get_contract()
            self.assertEqual(
                str(ex.exception), 'Unable to get token: test error')

    def test_get_contract_malformed(self):
        with mock.patch('downstream_farmer.client.requests.get') as patch:
            patch.return_value.json.return_value = {"invalid": "dict"}
            with self.assertRaises(DownstreamError) as ex:
                self.client.get_contract()
            self.assertEqual(
                str(ex.exception), 'Malformed response from server.')

    def test_get_contract_working(self):
        self.client.heartbeat = self.test_heartbeat
        with mock.patch('downstream_farmer.client.requests.get') as patch:
            inst = patch.return_value
            inst.json.return_value = MockValues.get_chunk_response
            contract = self.client.get_contract()
        self.assertEqual(
            contract.hash, self.test_contract.hash)
        self.assertEqual(
            contract.seed, self.test_contract.seed)
        self.assertEqual(
            contract.size, self.test_contract.size)
        self.assertEqual(
            contract.challenge, self.test_contract.challenge)
        self.assertAlmostEqual((contract.expiration - self.test_contract.expiration)
                               .total_seconds(), 0, delta=1)
        self.assertEqual(contract.tag, self.test_contract.tag)
    
    def inject_contract_pool(self):
        self.client.contract_pools.append(self.test_contract_pool)
    
    def test_contract_count(self):
        self.inject_contract_pool()
        self.assertEqual(self.client.contract_count(), 1)
    
    def test_heartbeat_count(self):
        self.inject_contract_pool()        
        self.test_contract_pool.heartbeat_count = 1
        self.assertEqual(self.client.heartbeat_count(), 1)
        
    def inject_mock_contract_pool(self):
        self.mock_contract_pool = mock.MagicMock()
        self.client.contract_pools.append(self.mock_contract_pool)
        
    def test_add_contract_to_existing_pool(self):
        self.inject_mock_contract_pool()
        self.mock_contract_pool.get_average_load.return_value = 0
        self.client._add_contract(self.test_contract)
        self.mock_contract_pool.add_contract.assert_called_with(self.test_contract)
    
    def test_add_contract_to_new_pool(self):
        self.inject_mock_contract_pool()
        self.mock_contract_pool.get_average_load.return_value = 1
        contract_pool = mock.MagicMock()
        with mock.patch('downstream_farmer.client.ContractPool') as pool_patch:
            pool_patch.return_value = contract_pool
            self.client._add_contract(self.test_contract)
        self.assertTrue(contract_pool.start.called)
        contract_pool.add_contract.assert_called_with(self.test_contract)
        self.assertEqual(len(self.client.contract_pools), 2)
        self.assertEqual(self.client.contract_pools[1], contract_pool)
        
    def test_remove_all_contracts(self):
        self.inject_mock_contract_pool()
        self.assertEqual(len(self.client.contract_pools), 1)
        self.client._remove_all_contracts()
        self.assertEqual(len(self.client.contract_pools), 0)
        self.assertTrue(self.mock_contract_pool.remove_all_contracts.called)
    
    def setup_run_mocks(self):
        self.client.thread_manager = mock.MagicMock()
        self.client.thread_manager.running = True
        self.client.get_contract = mock.MagicMock()
        self.client.get_contract.return_value = self.test_contract
        self.client._add_contract = mock.MagicMock()
        self.client.contract_thread = mock.MagicMock()
        self.client.get_total_size = mock.MagicMock()
        self.client.get_total_size.return_value = 0
    
    def test_run_contract_manager(self):
        self.setup_run_mocks()
        
        self.client.contract_thread.wait.side_effect = \
            MockContractShutdown(self.client.thread_manager)
        
        self.client._add_contract.side_effect = AddContractMock(self.client)
        
        self.client._run_contract_manager()
        
        self.assertFalse(self.client.thread_manager.signal_shutdown.called)
        self.client._add_contract.assert_called_with(self.test_contract, False)

    def test_run_contract_manager_obtain_fail_no_retry(self):
        self.setup_run_mocks()
        
        self.client.contract_count = mock.MagicMock()
        self.client.contract_count.return_value = 0
        self.client.get_contract.side_effect = DownstreamError('test error')
        
        self.client.thread_manager.signal_shutdown.side_effect = \
            MockContractShutdown(self.client.thread_manager)
            
        self.client._run_contract_manager()
            
        self.assertTrue(self.client.thread_manager.signal_shutdown.called)

    def test_run_contract_manager_obtain_fail_retry(self):
        self.setup_run_mocks()
        
        self.client.contract_count = mock.MagicMock()
        self.client.contract_count.return_value = 0
        self.client.get_contract.side_effect = \
            [DownstreamError('test error'), self.test_contract]
        
        self.client._add_contract.side_effect = AddContractMock(self.client)
        
        self.client.contract_thread.wait.side_effect = \
            MockContractShutdown(self.client.thread_manager)
        
        self.client._run_contract_manager(retry=True)
        
        self.assertFalse(self.client.thread_manager.signal_shutdown.called)
        
    def test_run_contract_manager_fail_after_acquisition(self):
        self.setup_run_mocks()
        
        self.client.contract_count = mock.MagicMock()
        self.client.contract_count.return_value = 1
        
        self.client.get_contract.side_effect = DownstreamError('test error')
        
        self.client._add_contract.side_effect = AddContractMock(self.client)
        
        self.client.contract_thread.wait.side_effect = \
            MockContractShutdown(self.client.thread_manager)
            
        self.client._run_contract_manager()
        
        self.assertFalse(self.client.thread_manager.signal_shutdown.called)
    
    def test_run_contract_manager_shutdown_during_acquisition(self):
        self.setup_run_mocks()
        
        self.client._add_contract.side_effect = \
            AddContractMock(self.client, self.client.thread_manager)
        
        self.client._run_contract_manager()
        
        self.assertFalse(self.client.thread_manager.signal_shutdown.called)
        
    def test_run_contract_manager_number_requirement(self):
        self.setup_run_mocks()
        
        self.client._add_contract.side_effect = \
            AddContractMock(self.client)
        
        self.client.heartbeat_count = mock.MagicMock()
        self.client.heartbeat_count.return_value = 1
        
        self.client.thread_manager.signal_shutdown.side_effect = \
            MockContractShutdown(self.client.thread_manager)
            
        self.client._run_contract_manager(number=1)
        
        self.assertTrue(self.client.thread_manager.signal_shutdown.called)
        
    def test_run_async(self):
        self.client.thread_manager = mock.MagicMock()
        self.contract_thread = mock.MagicMock()
        self.client.thread_manager.create_thread.return_value = self.contract_thread
        
        self.client.run_async()
        
        self.assertTrue(self.contract_thread.start.called)
        
class TestExceptions(unittest.TestCase):

    def test_downstream_error(self):
        e = DownstreamError('Test Exception')
        self.assertEqual(str(e), 'Test Exception')


class TestSmartFormatter(unittest.TestCase):
    def setUp(self):
        self.width = 80

    def test_raw(self):
        formatter = shell.SmartFormatter(None)
        raw_string = 'R|sample text blah this is a long piece of '\
            'text that should be split over lines but wont be because its raw text'\
            'blah!!!  and will split over new lines\nthis should be a on a new line'
        value = formatter._split_lines(raw_string, self.width)
        self.assertEqual(value, raw_string[2:].splitlines())
    
    def test_normal(self):
        formatter = shell.SmartFormatter(None)
        raw_string = 'This is a raw string that will be split over lines because '\
            'it will go into the HelpFormatter.  but This string needs to be longer'\
            'than 80 chars to split on the lines'
        value = formatter._split_lines(raw_string, self.width)
        self.assertEqual(value, HelpFormatter._split_lines(formatter, raw_string, self.width))


class TestShell(unittest.TestCase):

    def setUp(self):
        self._old_argv = sys.argv
        sys.argv = [
            'downstream'
        ]

    def tearDown(self):
        sys.argv = self._old_argv

    def test_fail_exit(self):
        with self.assertRaises(SystemExit):
            shell.fail_exit('Test')

    def test_eval_args_run(self):
        with mock.patch('downstream_farmer.shell.Farmer') as farmer:
            shell.eval_args(mock.MagicMock())
        self.assertTrue(farmer.called)
        self.assertTrue(farmer.return_value.run.called)

    def test_eval_args_downstream_error(self):
        with mock.patch('downstream_farmer.shell.Farmer') as farmer:
            farmer.side_effect = DownstreamError('error')
            with self.assertRaises(SystemExit):
                shell.eval_args(None)

    def test_eval_args_exception(self):
        with mock.patch('downstream_farmer.shell.Farmer') as farmer:
            farmer.side_effect = Exception('error')
            with self.assertRaises(SystemExit):
                shell.eval_args(None)

    def test_eval_args_catchall(self):
        with mock.patch('downstream_farmer.shell.Farmer') as farmer:
            farmer.side_effect = BaseException('error')
            with self.assertRaises(SystemExit):
                shell.eval_args(None)

    def test_parse_args(self):
        args = shell.parse_args()
        self.assertIsInstance(args, Namespace)

    def test_parse_args_version(self):
        with self.assertRaises(SystemExit):
            sys.argv.append('--version')
            shell.parse_args()

    def test_parse_args_number(self):
        sys.argv.append('--number')
        sys.argv.append('1')
        args = shell.parse_args()
        self.assertEqual(args.number, int(sys.argv[2]))

    def test_parse_args_number_default(self):
        args = shell.parse_args()
        self.assertEqual(args.number, None)

    def test_parse_args_path(self):
        sys.argv.append('--history')
        sys.argv.append('testpath')
        args = shell.parse_args()
        self.assertEqual(args.history, sys.argv[2])

    def test_parse_args_history_default(self):
        args = shell.parse_args()
        self.assertEqual(args.history, os.path.join('data', 'history.json'))

    def test_parse_args_size(self):
        sys.argv.append('--size')
        sys.argv.append('10')
        args = shell.parse_args()
        self.assertEqual(args.size, int(sys.argv[2]))

    def test_parse_args_size_default(self):
        args = shell.parse_args()
        self.assertEqual(args.size, 100)

    def test_parse_args_address(self):
        sys.argv.append('--address')
        sys.argv.append('testaddress')
        args = shell.parse_args()
        self.assertEqual(args.address, sys.argv[2])

    def test_parse_args_address_default(self):
        args = shell.parse_args()
        self.assertEqual(args.address, None)

    def test_parse_args_token(self):
        sys.argv.append('--token')
        sys.argv.append('testtoken')
        args = shell.parse_args()
        self.assertEqual(args.token, sys.argv[2])

    def test_parse_args_token_default(self):
        args = shell.parse_args()
        self.assertEqual(args.token, None)

    def test_parse_args_url(self):
        sys.argv.append('testurl')
        args = shell.parse_args()
        self.assertEqual(args.node_url, sys.argv[1])

    def test_parse_args_url_default(self):
        args = shell.parse_args()
        self.assertEqual(args.node_url, None)

    def test_main(self):
        with mock.patch('downstream_farmer.shell.parse_args') as pa:
            with mock.patch('downstream_farmer.shell.eval_args') as ea:
                shell.main()
                self.assertTrue(pa.called)
                self.assertTrue(ea.called)


class MockValues:
    connect_response = {
        "heartbeat": "AQoAAACAAAAAgAAAAJCTCchnuw8nE9FbjUyJVNNzjQumBHHw7iFL5Ply"
                     "4vHQvkqOqcgc5XKXgWVaJGCs1F+oI68zL9Ir9+q0BkA5WadDq5uz0Cot"
                     "sY8Pad8UemCLvLGNlnkavsbn0dXk7/0QL5KYGardu9m5zWtQEagdvl86"
                     "tSbksec1B5Y9K1S5hGlr",
        "token": "b45a3e2932c87474cb1bd7e642cf792b",
        "type": "Swizzle"
    }

    get_chunk_response = {
        "challenge": "AQAAACAAAACJwjEuYPkbnGOppNVgG0Xc5GKgp0g2kGN2bMCssbMBwIAA"
                     "AACQkwnIZ7sPJxPRW41MiVTTc40LpgRx8O4hS+T5cuLx0L5KjqnIHOVy"
                     "l4FlWiRgrNRfqCOvMy/SK/fqtAZAOVmnQ6ubs9AqLbGPD2nfFHpgi7yx"
                     "jZZ5Gr7G59HV5O/9EC+SmBmq3bvZuc1rUBGoHb5fOrUm5LHnNQeWPStU"
                     "uYRpaw==",
        "due": "60",
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
        "due": "60",
        "answered": True
    }
