import os
import logging
import traceback
import sys
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
        line = line[:self.col] + field_text + line[self.col+self.width:]
        return line

    def get_text(self, value, lpad=' '):
        field_text = lpad+str(value)
        if (len(field_text) > self.width):
            field_text = field_text[:self.width]
        else:
            field_text = field_text.ljust(self.width)
        return field_text

class CLIProgressBar(CLIField):
    def get_text(self, value, lpad=''):
         # value is a fraction of space to be filled with #
        chars = int(value*float(self.width))
        text = '#'*chars
        return CLIField.get_text(self, text, '')

template = [
'+---------------------------Storj Downstream-Farmer---------------------------+',
'| Connected Node :                                                            |',
'| Uptime         : 0:00:00.000000                                             |',
'| SJCX Address   :                                                            |',
'| Token          :                                                            |',
'| Heartbeats     : 0                                                          |',
'|                                                                             |',
'+-Contract Information--------------------------------------------------------+',
'| Contracts : 0       Filled / Available : 0.0 B / 0.0 B (0.0%)               |',
'| Updating  : 0               Submitting : 0             Proving : 0          |',
'|                                                                             |',
'+-Drive Space Used------------------------------------------------------------|',
'| 0                 25                 50                75               100 |',
'|                                                                             |',
'|                                                                             |',
'+-Performance Stats-----------------------------------------------------------+',
'| Worker Threads :   0       Avg. Load :    0.0%       Max Load :    0.0%     |',
'|                                                                             |',
'+-Status----------------------------------------------------------------------+',
'|                                                                             |',
'+-----------------------------------------------------------------------------+']

fields = [CLIField('node_url',1,18,59),
          CLIField('uptime',2,18,59),
          CLIField('sjcx_address',3,18,59),
          CLIField('token',4,18,59),
          CLIField('heartbeats',5,18,59),
          CLIField('contracts',8,13,9),
          CLIField('filled',8,42,36),
          CLIField('updating',9,13,17),
          CLIField('submitting',9,42,15),
          CLIField('proving',9,66,12),
          CLIProgressBar('space_bar',13,2,75),
          CLIField('worker_threads',16,18,11),
          CLIField('avg_load',16,40,15),
          CLIField('max_load',16,65,13),
          CLIField('status',19,1,77)]


class CLIStats(object):
    def __init__(self, template, fields):
        self.template = template
        self.fields = fields
        self.values = dict()
        self._update_index()
        self.write_lock = threading.Lock()
        
    def _update_index(self):
        lines_with_fields = set([f.row for f in self.fields])
        self.fields_by_line = {l:[f for f in fields if f.row == l] for l in lines_with_fields}
        self.fields_by_name = {f.name:f for f in fields}
    
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
            self.pos_print(len(self.template)+2, 1, '')
        
    def print_field(self, field_name):
        f = self.fields_by_name[field_name]
        text = f.get_text(self.values[field_name])
        with self.write_lock:
            self.pos_print(f.row+1, f.col+1, text)
        
    def update_all(self):
        try:
            for f in self.fields:
                self.print_field(f.name)
            self.reset_cursor()
        except:
            logger.debug(traceback.format_exc())

            
class FarmerCLIStats(CLIStats):
    def __init__(self):
        CLIStats.__init__(self, template, fields)
        

class CLIStatusStream(object):
    def __init__(self, stats, field_name):
        self.stats = stats
        self.field_name = field_name
        
    def write(self, data):
        logger.debug('setting {0} with {1}'.format(self.field_name,data))
        data = data.rstrip()
        if (len(data) > 0):
            self.stats.set(self.field_name, data,flush=False)

    def flush(self):
        logger.debug('flush called')
        self.stats.print_field(self.field_name)
        self.stats.reset_cursor()
        
class CLIStatusHandler(logging.StreamHandler):
    def __init__(self, stats, field_name):
        logging.StreamHandler.__init__(self, CLIStatusStream(stats, field_name))