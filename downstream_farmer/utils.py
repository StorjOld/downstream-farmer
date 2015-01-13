#!/usr/bin/env python
# -*- coding: utf-8 -*-


import six
import os
import sys
import traceback
import signal
import json
import threading
import time

from collections import deque

from .exc import DownstreamError


def urlify(string):
    """ You might be wondering: why is this here at all, since it's basically
    doing exactly what the quote_plus function in urllib does. Well, to keep
    the 2 & 3 stuff all in one place, meaning rather than try to import the
    urllib stuff twice in each file where url-safe strings are needed, we keep
    it all in one file: here.

    Supporting multiple Pythons is hard.

    :param string: String to URLify
    :return: URLified string
    """
    return six.moves.urllib.parse.quote(string)


def handle_json_response(resp):
    """This function handles a response from the downstream-node server.
    If the server responds with an error, we attempt to get the json item
    'message' from the body.  if that fails, we just raise a regular http
    error.
    otherwise, if the server responds with a 200 'ok' message, we parse the
    json.

    :param resp: the flask request response to handle
    :returns: the parsed json as an object
    """
    if (resp.status_code != 200):
        try:
            # see if we have any json to parse
            r_json = resp.json()
            message = r_json['message']
        except:
            # if not, just raise the regular http error
            # dump error:
            print(resp)
            resp.raise_for_status()
        else:
            raise DownstreamError(message)

    # status code is 200, we should be good.
    r_json = resp.json()

    return r_json


def resource_path(relative):
    return os.path.join(
        getattr(sys, '_MEIPASS',
                os.path.join(os.path.dirname(__file__), 'data')),
        relative)


def save(path, obj):
    """saves the farmer state to disk

    :param path: the path to save to
    :param obj: the object to save (must be json serializable)
    """
    (head, tail) = os.path.split(path)
    if (len(head) > 0 and not os.path.isdir(head)):
        os.mkdir(head)
    with open(path, 'w+') as f:
        json.dump(obj, f)


def restore(path):
    """restores state from disk

    :param path: the path to restore from
    :returns: the object restored, or an empty dict(), if the file doesn't
        exist
    """
    if (os.path.exists(path)):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as ex:
            raise DownstreamError(
                'Couldn\'t parse \'{0}\': {1}'.format(path, str(ex)))
    else:
        return dict()


class ManagedThread(threading.Thread):

    def __init__(self, target=None, name=None, args=(), kwargs={}):
        """Initializes the managed thread

        A managed thread basically has an attached event which can awake
        that thread from sleeping.
        """
        threading.Thread.__init__(self, None, target, name, args, kwargs)
        self.daemon = True
        self.attached_event = threading.Event()

    def wait(self, timeout=None):
        self.attached_event.wait(timeout)
        self.attached_event.clear()

    def wake(self):
        self.attached_event.set()


class ThreadManager(object):

    def __init__(self):
        self.threads = list()
        self.shutting_down = threading.Event()

    def signal_shutdown(self):
        """Can be called from any thread, signals for a shutdown to occur.
        """
        if (self.running):
            print('Shutting down...')
        self.shutting_down.set()
        # wake all the child thread if they are waiting on a signal
        for t in self.threads:
            t.wake()

    def sleep(self, timeout):
        """Calls the wait function on the current ManagedThread
        Should be called from within a managed thread.
        Use this instead of time.sleep() so that the managed thread
        can be awoken and shutdown
        :param timeout: the timeout for the sleep.  If none, will sleep
        indefinitely
        """
        if (self.running):
            threading.current_thread().wait(timeout)

    @property
    def running(self):
        return not self.shutting_down.is_set()

    def finish(self):
        """Signals for a shutdown and waits for child
        threads to exit
        Should be called from the main thread
        """
        self.signal_shutdown()
        # wait for child threads to shut down
        for t in self.threads:
            if (t.is_alive()):
                t.join()
        self.threads = list()

    def _child_wrapper(self, target=None, args=(), kwargs={}):
        try:
            target(*args, **kwargs)
        except:
            traceback.print_exc()
            self.signal_shutdown()

    def create_thread(self, target=None, args=(), kwargs={}):
        thread = ManagedThread(
            target=self._child_wrapper, args=(target, args, kwargs))
        self.threads.append(thread)
        return thread

    def wait_for_shutdown(self):
        """Waits for a shutdown signal from the child threads
        Should be run from the main thread
        """
        while (self.running):
            # we have to sleep in order to receive sigint on windows
            # this should work for linux too
            # this is a 1 second polling solution.  not ideal.
            # the other option would be to have the dying child threads
            # send a kill signal when they fail
            try:
                time.sleep(1)
            except:
                # when interrupted this sleep will raise the interrupted error
                pass
        self.finish()


class ShellApplication(ThreadManager):

    def __init__(self):
        """Initializes the shell application by registering some signals
        Must be called from the main thread
        """
        ThreadManager.__init__(self)

        # register signals with application
        for sig in [signal.SIGTERM, signal.SIGINT]:
            signal.signal(sig, self.signal_handler)

    def signal_handler(self, signum=None, frame=None):
        """When called, exits the shell application.  Calls the shutdown
        function
        """
        self.signal_shutdown()


class WorkChunk(object):

    """Encapsulates a chunk of work for the load tracker
    """

    def __init__(self, start, end):
        self.start = start
        self.end = end

    @property
    def elapsed(self):
        """The elapsed time for the chunk
        """
        return self.end - self.start

    def elapsed_from_start(self, start):
        """Time elapsed in the work chunk, given a start time
        Ensures that the chunk work cannot start any earlier than
        the specified start time.
        :param start: the earliest time to calculate the elapsed time from
        """
        if (self.start < start):
            return self.end - start
        else:
            return self.elapsed


class LoadTracker(object):

    def __init__(self, sample_time=60):
        self.lock = threading.RLock()
        self.work_chunks = deque()
        self.current_work_start = None
        self.sample_time = sample_time
        self.start = time.time()

    @property
    def sample_start(self):
        sample_start = time.time() - self.sample_time
        if (sample_start < self.start):
            sample_start = self.start
        return sample_start

    def _trim(self):
        # trim work chunks
        with self.lock:
            while (len(self.work_chunks) > 0 and
                    self.work_chunks[0].end < self.sample_start):
                self.work_chunks.popleft()

    def start_work(self):
        with self.lock:
            self.current_work_start = time.time()

    def finish_work(self):
        with self.lock:
            if (self.current_work_start is None):
                raise RuntimeError('Load tracker work chunk must be started '
                                   'before it can be finished.')
            self.work_chunks.append(
                WorkChunk(self.current_work_start, time.time()))
            self.current_work_start = None
            self._trim()

    def work_time(self):
        with self.lock:
            self._trim()
            sample_start = self.sample_start
            work_total = 0
            for c in self.work_chunks:
                work_total += c.elapsed_from_start(sample_start)
            # add any current work
            if (self.current_work_start is not None):
                work_total += WorkChunk(self.current_work_start,
                                        time.time()).\
                    elapsed_from_start(sample_start)
        return work_total

    def total_time(self):
        return time.time() - self.sample_start

    def load(self):
        return float(self.work_time()) / float(self.total_time())
