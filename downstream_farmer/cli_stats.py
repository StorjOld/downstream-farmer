
from __future__ import print_function
import os
import logging
import traceback
import colorama
import threading

logger = logging.getLogger('downstream_farmer.cli_stats')


class CLIField(object):

    def __init__(self, name, row, col, width):
        self.name = name
        self.row = row
        self.col = col
        self.width = width

    def update_line(self, line, value, lpad=' '):
        field_text = self.get_text(value, lpad)
        line = line[:self.col] + field_text + line[self.col + self.width:]
        return line

    def get_text(self, value, lpad=' '):
        field_text = lpad + str(value)
        if (len(field_text) > self.width):
            field_text = field_text[:self.width]
        else:
            field_text = field_text.ljust(self.width)
        return field_text


class CLIProgressBar(CLIField):

    def get_text(self, value, lpad=''):
        # value is a fraction of space to be filled with #
        chars = int(value * float(self.width))
        text = '#' * chars
        return CLIField.get_text(self, text, '')


class Stats(object):

    def __init__(self):
        pass

    def set(self, field, value, flush=True):
        pass


class CLIStats(Stats):

    def __init__(self, template=[], fields=[]):
        self.template = template
        self.fields = fields
        self.values = dict()
        self.fields_by_name = dict()
        self.write_lock = threading.Lock()
        self._update_index()

    def _update_index(self):
        self.fields_by_name = {f.name: f for f in self.fields}

    def set(self, field, value, flush=True):
        self.values[field] = value
        if (flush):
            self.print_field(field)
            self.reset_cursor()

    def init(self):
        colorama.init()
        os.system('cls' if os.name == 'nt' else 'clear')
        for l in self.template:
            print(l)

    def pos_print(self, y, x, text):
        print('\x1b[%d;%dH%s' % (y, x, text), end='')

    def reset_cursor(self):
        with self.write_lock:
            self.pos_print(len(self.template) + 2, 1, '')

    def print_field(self, field_name):
        if (field_name in self.fields_by_name):
            f = self.fields_by_name[field_name]
            text = f.get_text(self.values[field_name])
            with self.write_lock:
                self.pos_print(f.row + 1, f.col + 1, text)

    def update_all(self):
        try:
            for f in self.fields:
                self.print_field(f.name)
            self.reset_cursor()
        except:
            logger.debug(traceback.format_exc())


class CLIStatusStream(object):

    def __init__(self, stats, field_name):
        self.stats = stats
        self.field_name = field_name

    def write(self, data):
        data = data.split('\n')[0]
        if (len(data) > 0):
            self.stats.set(self.field_name, data, flush=False)

    def flush(self):
        self.stats.print_field(self.field_name)
        self.stats.reset_cursor()


class CLIStatusHandler(logging.StreamHandler):

    def __init__(self, stats, field_name):
        logging.StreamHandler.__init__(
            self, CLIStatusStream(stats, field_name))
