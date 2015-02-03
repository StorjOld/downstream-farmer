from .cli_stats import CLIStats, CLIField, CLIProgressBar

template = [
    '+---------------------------Storj Downstream-Farmer---------------------------+',  # NOQA
    '| Connected Node :                                                            |',  # NOQA
    '| Uptime         : 0:00:00                                                    |',  # NOQA
    '| SJCX Address   :                                                            |',  # NOQA
    '| Token          :                                                            |',  # NOQA
    '| Heartbeats     : 0                                                          |',  # NOQA
    '|                                                                             |',  # NOQA
    '+-Contract Information--------------------------------------------------------+',  # NOQA
    '| Contracts : 0       Filled / Available : 0.0 B / 0.0 B (0.0%)               |',  # NOQA
    '| Updating  : 0               Submitting : 0             Proving : 0          |',  # NOQA
    '|                                                                             |',  # NOQA
    '+-Drive Space Used------------------------------------------------------------+',  # NOQA
    '| 0                 25                 50                75               100 |',  # NOQA
    '|                                                                             |',  # NOQA
    '|                                                                             |',  # NOQA
    '+-Performance Stats-----------------------------------------------------------+',  # NOQA
    '| Worker Threads : 0         Avg. Load : 0.0%          Max Load : 0.0%        |',  # NOQA
    '|                                                                             |',  # NOQA
    '+-Status----------------------------------------------------------------------+',  # NOQA
    '|                                                                             |',  # NOQA
    '+-----------------------------------------------------------------------------+']  # NOQA

fields = [CLIField('node_url', 1, 18, 59),
          CLIField('uptime', 2, 18, 59),
          CLIField('sjcx_address', 3, 18, 59),
          CLIField('token', 4, 18, 59),
          CLIField('heartbeats', 5, 18, 59),
          CLIField('contracts', 8, 13, 9),
          CLIField('filled', 8, 42, 36),
          CLIField('updating', 9, 13, 17),
          CLIField('submitting', 9, 42, 15),
          CLIField('proving', 9, 66, 12),
          CLIProgressBar('space_bar', 13, 2, 75),
          CLIField('worker_threads', 16, 18, 11),
          CLIField('avg_load', 16, 40, 15),
          CLIField('max_load', 16, 65, 13),
          CLIField('status', 19, 1, 77)]


class FarmerCLIStats(CLIStats):

    def __init__(self):
        CLIStats.__init__(self, template, fields)
