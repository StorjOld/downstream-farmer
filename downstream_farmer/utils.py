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
import logging

from collections import deque
from six.moves.queue import PriorityQueue
from datetime import datetime, timedelta

from .exc import DownstreamError
from .cli_stats import Stats

logger = logging.getLogger('storj.downstream_farmer.utils')


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
            logger.debug(resp)
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


def sizeof_fmt(num, suffix='B'):
    """
    From: http://stackoverflow.com/questions/1094841/reusable-library-to-get-human-readable-version-of-file-size  # NOQA
    Written by Fred Cirera
    """
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)


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
        """This will wait until wake is called but no longer than the specified
        timeout.
        """
        # timeout_string = 'indefinitely' if timeout is None \
        #    else '{0} seconds'.format(timeout)
        # print('Thread {0} sleeping {1}'.format(self, timeout_string))
        self.attached_event.wait(timeout)
        # print('Thread {0} awoken'.format(self))
        # if wake is called now, it is ok, because the thread is already awake.
        self.attached_event.clear()
        # if wake is called now, the next wait call will not block

    def wake(self):
        self.attached_event.set()


class ThreadManager(object):

    def __init__(self):
        self.threads = list()
        self.shutting_down = threading.Event()
        self.logger = logging.getLogger(
            'storj.downstream_farmer.utils.ThreadManager')

    def signal_shutdown(self):
        """Can be called from any thread, signals for a shutdown to occur.
        """
        if (self.running):
            self.logger.info('Shutting down...')
        self.shutting_down.set()
        # wake all the child thread if they are waiting on a signal
        for t in self.threads:
            t.wake()

    def sleep(self, timeout=None):
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
            self.logger.debug(
                'Starting {0}'.format(threading.current_thread()))
            target(*args, **kwargs)
            self.logger.debug(
                '{0} finished'.format(threading.current_thread()))
        except:
            self.logger.debug(traceback.format_exc())
            self.logger.info(sys.exc_info()[1])
            self.signal_shutdown()

    def create_thread(self, name=None, target=None, args=(), kwargs={}):
        thread = ManagedThread(name=name,
                               target=self._child_wrapper,
                               args=(target, args, kwargs))
        self.threads.append(thread)
        return thread

    def called_every_second(self):
        """This function is called every second the thread manager is running.
        """

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
                self.called_every_second()
                time.sleep(1)
            except:
                # when interrupted this sleep will raise the interrupted error
                pass
        self.finish()


class WorkItem(object):

    def __init__(self, target=None, args=[], kwargs={}, priority=50):
        self.target = target
        self.args = args
        self.kwargs = kwargs
        self.priority = priority

    def __call__(self):
        self.target(*self.args, **self.kwargs)

    def __lt__(self, other):
        return self.priority < other.priority


class WorkerThread(threading.Thread):

    def __init__(self, thread_pool=None):
        """Initializes the worker thread

        A worker thread has an attached load tracker
        """
        threading.Thread.__init__(self, target=self._run)
        self.logger = logging.getLogger(
            'storj.downstream_farmer.utils.WorkerThread')
        self.daemon = True
        self.load_tracker = LoadTracker()
        self.thread_pool = thread_pool
        self.running = True

    def stop(self):
        """Stops the worker thread after it finishes it's next batch of work
        It will zombify this thread.
        """
        self.running = False

    def _run(self):
        """this thread will run unmanaged, and so will die dirty when program
        closes.  therefore we use a monitor thread to make sure any
        unfinished work is done before the program shuts down
        """
        self.load_tracker.start_work()
        while self.running:
            # print('{0} : waiting on work'.format(threading.current_thread()))

            self.load_tracker.finish_work()
            # print('{0} : finished work, load: {1}%'.
            #       format(threading.current_thread(),
            #              round(self.load_tracker.load()*100.0, 2)))
            work = self.thread_pool.tasks.get()
            self.load_tracker.start_work()
            try:
                # print('{0} : starting work'
                #       .format(threading.current_thread()))
                work()
            except:
                self.logger.debug(traceback.format_exc())
                self.thread_pool.thread_manager.signal_shutdown()
            # print('{0} : done working'.format(threading.current_thread()))
            self.thread_pool.tasks.task_done()


class ThreadPool(object):

    def __init__(self, thread_manager, thread_count=10):
        """Initialization method

        :param thread_manager: the thread manager to use
        :param thread_count: the number of workers to instantiate
        """
        self.logger = logging.getLogger(
            'storj.downstream_farmer.utils.ThreadPool')
        self.tasks = PriorityQueue()
        self.thread_manager = thread_manager
        self.workers = list()
        self.workers_lock = threading.Lock()
        self.max_thread_count = 50
        self.load_minimum = 0.01
        self.load_maximum = 0.5
        # managed monitor thread
        self.monitor_thread = self.thread_manager.create_thread(
            name='MonitorThread',
            target=self._monitor)
        for i in range(0, thread_count):
            self._add_thread()

    def thread_count(self):
        with self.workers_lock:
            return len(self.workers)

    def _add_thread(self):
        # unmanaged worker threads
        if (len(self.workers) < self.max_thread_count):
            self.logger.debug(
                '{0} : adding worker'.format(threading.current_thread()))
            worker = WorkerThread(self)
            with self.workers_lock:
                self.workers.append(worker)
            return worker
        else:
            return None

    def _remove_thread(self):
        with self.workers_lock:
            if (len(self.workers) > 1):
                self.logger.debug(
                    '{0} : removing worker'.format(threading.current_thread()))
                # make sure to retain one worker
                thread = self.workers.popleft()
                thread.stop()

    def calculate_loading(self):
        total_time = 0
        work_time = 0
        with self.workers_lock:
            for w in self.workers:
                total_time += w.load_tracker.total_time()
                work_time += w.load_tracker.work_time()
        if (total_time > 0):
            load = float(work_time) / float(total_time)
        else:
            load = 0
        return load

    def max_load(self):
        max = 0
        with self.workers_lock:
            for w in self.workers:
                load = w.load_tracker.load()
                if (load > max):
                    max = load
        return max

    def check_loading(self):
        self.monitor_thread.wake()

    def _monitor(self):
        """This runs until the thread manager wakes it up during
        shutdown, at which time it will wait for any unfinished work in the
        queue, and then finish, allowing the program to exit
        """
        # wait until shutdown is called
        while (self.thread_manager.running):
            # check loading every second to see if we should add another
            # thread.
            load = self.calculate_loading()
            if (load > self.load_maximum):
                worker = self._add_thread()
                if (worker is not None):
                    worker.start()
            elif (load < self.load_minimum):
                self._remove_thread()
            self.thread_manager.sleep(10)
        # wait for any existing work to finish
        self.logger.debug('MonitorThread waiting for tasks to finish')
        self.tasks.join()
        self.logger.debug('MonitorThread finishing')
        # now, managed thread can exit so program can close cleanly

    def put_work(self, target, args=[], kwargs={}, priority=50):
        """Puts work in the work queue.
        :param work: callable work object
        """
        self.tasks.put(WorkItem(target, args, kwargs, priority))

    def start(self):
        """Starts the thread pool and all its workers and the monitor thread
        """
        with self.workers_lock:
            for worker in self.workers:
                worker.start()
        self.monitor_thread.start()


class ShellApplication(ThreadManager):

    def __init__(self):
        """Initializes the shell application by registering some signals
        Must be called from the main thread
        """
        ThreadManager.__init__(self)

        # register signals with application
        for sig in [signal.SIGTERM, signal.SIGINT]:
            signal.signal(sig, self.signal_handler)

        self.stats = Stats()

    def signal_handler(self, signum=None, frame=None):
        """When called, exits the shell application.  Calls the shutdown
        function
        """
        self.signal_shutdown()


class Counter(object):

    def __init__(self, zero_callback=None):
        self.count = 0
        self.lock = threading.Lock()
        self.zero_callback = zero_callback

    def add(self, number):
        with self.lock:
            self.count += number
            if (self.zero_callback is not None and self.count == 0):
                self.zero_callback()

    def __call__(self, number=1):
        return CounterContext(self, number)


class CounterContext(object):

    def __init__(self, counter, increment):
        self.counter = counter
        self.increment = increment

    def __enter__(self):
        self.counter.add(self.increment)

    def __exit__(self, type, value, traceback):
        self.counter.add(-self.increment)


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
        self.start = time.clock()

    @property
    def sample_start(self):
        sample_start = time.clock() - self.sample_time
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
            self.current_work_start = time.clock()

    def finish_work(self):
        with self.lock:
            if (self.current_work_start is None):
                raise RuntimeError('Load tracker work chunk must be started '
                                   'before it can be finished.')
            self.work_chunks.append(
                WorkChunk(self.current_work_start, time.clock()))
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
                                        time.clock()).\
                    elapsed_from_start(sample_start)
        return work_total

    def total_time(self):
        return time.clock() - self.sample_start

    def load(self):
        total = self.total_time()
        if (total > 0):
            return float(self.work_time()) / float(total)
        else:
            return 0


class BurstQueueItem(object):

    """This class encapsulates an item that has a due date where where an
    activity must be performed on the item before that due date, but after
    the earliest time specified.

    The due date indicates that the action must be performed as soon as
    possible, while ready indicates whether the action can be performed.
    basically, it can be performed any time between earliest and the due
    date, but must be performed soon after the due date
    """

    def __init__(self, item, due, earliest=None):
        self.item = item
        self.due = due
        self.earliest = earliest

    def is_due(self):
        return self.due < datetime.utcnow()

    def is_ready(self):
        if (self.earliest is None):
            return True
        return self.earliest < datetime.utcnow()


class RateLimit(object):

    """Simple rate limiter with no bursting
    :param rate: in seconds per request
    """

    def __init__(self, rate=None):
        self.rate = timedelta(seconds=rate)
        self.last = datetime.utcnow() - self.rate

    def ping(self):
        if (self.rate is None or (datetime.utcnow() - self.last) > self.rate):
            self.last = datetime.utcnow()
            return True
        else:
            return False

    def peek(self):
        return self.rate is None or (datetime.utcnow() - self.last) > self.rate

    def next(self):
        """Returns the number of seconds until the next event can occur
        """
        if (self.peek()):
            return datetime.utcnow()
        else:
            return self.last + self.rate


class BurstQueue(object):

    """
    This class will help us perform heartbeats in a timely manner.

    Items can be placed in this queue.  Items have a 'due date'
    When `get` is called, it either returns an empty list if there are
    no due items, or if there are any due items, it will return
    all the items in the queue that are ready.
    Optionally it can have a rate limit to the number of time
    items can be retrieved, and also a full callback that occurs
    when the number of items exceeds a specified number
    """

    def __init__(self, rate=None, full_size=None, full_callback=None):
        self.queue = deque()
        self.queue_lock = threading.Lock()
        self.rate_limit = RateLimit(rate)
        self.set_full_callback(full_size, full_callback)

    def set_full_callback(self, full_size, full_callback):
        self.full_size = full_size
        self.full_callback = full_callback
        self.callback = (full_size is not None
                         and full_callback is not None)

    def put(self, item, due, earliest=None):
        with self.queue_lock:
            self.queue.append(BurstQueueItem(item, due, earliest))
            if (self.callback and len(self.queue) >= self.full_size):
                self.full_callback()

    def get(self):
        """Gets the list of ready items if any items are due"""
        if (self._any_due() and self.rate_limit.peek()):
            with self.queue_lock:
                ready_items = list()
                unready_items = deque()
                for i in self.queue:
                    if i.is_ready():
                        ready_items.append(i.item)
                    else:
                        unready_items.append(i)
                self.queue = unready_items
                self.rate_limit.ping()
                return ready_items
        else:
            return list()

    def next_due(self):
        """Gets the next due time
        """
        earliest = None
        with self.queue_lock:
            for queue_item in self.queue:
                if (earliest is None or queue_item.due < earliest):
                    earliest = queue_item.due
        if (earliest is not None):
            return max(earliest, self.rate_limit.next())
        else:
            return None

    def _any_due(self):
        """Returns whether any items are due
        """
        with self.queue_lock:
            if (self.callback and len(self.queue) > self.full_size):
                return True
            for queue_item in self.queue:
                if (queue_item.is_due()):
                    return True
        return False


class SimpleIterableJsonEncoder(json.JSONEncoder):

    def iterencode(self, o, _one_shot=False):
        try:
            # try base class method
            chunks = json.JSONEncoder.iterencode(self, o, _one_shot)
            for chunk in chunks:
                yield chunk
        except TypeError as ex:
            # type error... see if the item is iterable
            try:
                iterable = iter(o)
            except:
                raise ex
            else:
                # item is iterable
                yield '['
                buf = ''
                first = True
                for item in iterable:
                    if (first):
                        first = False
                    else:
                        buf = self.item_separator
                    chunks = self.iterencode(item)
                    for chunk in chunks:
                        yield buf + chunk
                yield ']'
