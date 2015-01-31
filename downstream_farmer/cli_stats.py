import os
import logging
import traceback
import sys
import colorama

logger = logging.getLogger('downstream_farmer.cli_stats')

class CLIField(object):
    def __init__(self, name, row, col, width):
        self.name = name
        self.row = row
        self.col = col
        self.width = width
        
    def update_line(self, line, value, lpad=' '):
        field_text = self.get_text(line, value, lpad)
        line = line[:self.col] + field_text + line[self.col+self.width:]
        return line

    def get_text(self, line, value, lpad=' '):
        field_text = lpad+str(value)
        if (len(field_text) > self.width):
            field_text = field_text[:self.width]
        else:
            field_text = field_text.ljust(self.width)
        return field_text

class CLIProgressBar(CLIField):
    def get_text(self, line, value, lpad=''):
         # value is a fraction of space to be filled with #
        chars = int(value*float(self.width))
        text = '#'*chars
        return CLIField.get_text(self, line, text, '')

template = [
'+---------------------------Storj Downstream-Farmer---------------------------+',
'| Connected Node :                                                            |',
'| Uptime :  0:00:00.000000                                                    |',
'|                                                                             |',
'+-Contract Information--------------------------------------------------------+',
'| Contracts : 0       Filled / Available :    0.0 B / 0.0 B ( 0.0%)           |',
'| Updating  : 0               Submitting :    0          Proving :     0      |',
'|                                                                             |',
'+-Drive Space Used------------------------------------------------------------|',
'|0                25                  50                 75                100|',
'|                                                                             |',
'|                                                                             |',
'+-Performance Stats-----------------------------------------------------------+',
'| Worker Threads :   0       Avg. Load :    0.0%       Max Load :    0.0%     |',
'|                                                                             |',
'+-----------------------------------------------------------------------------+']

fields = [CLIField('node_url',1,18,60),
          CLIField('uptime',2,10,68),
          CLIField('contracts',5,13,9),
          CLIField('filled',5,42,36),
          CLIField('updating',6,13,17),
          CLIField('submitting',6,42,15),
          CLIField('proving',6,66,12),
          CLIProgressBar('space_bar',10,1,77),
          CLIField('worker_threads',13,18,11),
          CLIField('avg_load',13,40,15),
          CLIField('max_load',13,65,13)]


class CLIStats(object):
    def __init__(self, template, fields):
        self.template = template
        self.fields = fields
        self.values = dict()
        self._update_index()
        
    def _update_index(self):
        lines_with_fields = set([f.row for f in self.fields])
        self.fields_by_line = {l:[f for f in fields if f.row == l] for l in lines_with_fields}
    
    def set(self, field, value):
        self.values[field] = value        
        
    def init(self):
        colorama.init()
        os.system('cls' if os.name == 'nt' else 'clear')
        for l in self.template:
            print(l)
        
    def pos_print(self, y, x, text):
        print('\x1b[%d;%dH%s' % (y, x, text), end='')
        
    def update(self):
        try:
            for i in range(0, len(self.template)):
                line = self.template[i]
                if i in self.fields_by_line:
                    for f in self.fields_by_line[i]:
                        if f.name not in self.values:
                            continue
                        text = f.get_text(line, self.values[f.name])
                        self.pos_print(f.row+1, f.col+1, text)
            self.pos_print(i+2, 1, ' ')
        except:
            logger.debug(traceback.format_exc())

            
class FarmerCLIStats(CLIStats):
    def __init__(self):
        CLIStats.__init__(self, template, fields)