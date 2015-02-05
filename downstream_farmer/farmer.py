import siggy
import os
import six
import sys
import logging
import datetime
from .utils import resource_path, restore, save, ShellApplication
from .client import DownstreamClient
from .exc import DownstreamError
from .cli_stats import CLIStatusHandler
from .farmer_stats import FarmerCLIStats


class Farmer(ShellApplication):

    def __init__(self, args):
        """The farmer should have some priorities on how it uses the
        parameters.

        1) if a url is not specified, it loads saved url and connects to that
           node
        2) if no node is specified on disk,  connect to our prototype node.
        3) if no token is specified, it attempts to load the token for the node
           from disk
        4) if no token is on disk, it will attempt to retrieve a new farming
           token from the node.  this requires an address.
        5) if no address is specified on the command line, it will attempt to
           load the address for the node from the identities file
        6) if no address is available, fail.
        7) if an address is given on the command line that is different from
           the saved address, it uses the specified address and obtains a new
           token

        :param args: the arguments from the command line
        """
        ShellApplication.__init__(self)

        self.set_up_logging(args)

        if (not args.quiet and not args.print_log):
            stats = FarmerCLIStats()
            stats.init()
            self.stats = stats
            status_handler = CLIStatusHandler(stats, 'status')
            status_handler.setLevel(logging.INFO)
            self.logger.addHandler(status_handler)
        elif (args.print_log):
            console_handler = logging.StreamHandler(stream=sys.stdout)
            console_handler.setLevel(logging.DEBUG)
            self.logger.addHandler(console_handler)

        self.cert_path = resource_path('ca-bundle.crt')
        self.verify_cert = not args.ssl_no_verify

        self.load_number(args)

        self.load_size(args)

        # restore history and identities from file, if possible
        self.history_path = args.history
        self.identity_path = args.identity
        self.chunk_dir = args.data_directory
        self.prepare_chunk_dir()

        self.state = restore(self.history_path)
        self.identities = restore(self.identity_path)

        self.load_url_and_check(args)

        self.load_token(args)

        self.load_address(args)

        self.load_signature(args)

        if (self.token is None and self.address is None):
            raise DownstreamError(
                'Must specify farming address if one is not available.')

        if (self.token is not None):
            self.logger.info('Using token {0}'.format(self.token))

        if (self.address is not None):
            self.logger.info('Farming on address {0}'.format(self.address))

        self.stats.set('sjcx_address', self.address)

    def set_up_logging(self, args):
        path = os.path.abspath(args.log_path)
        logging.basicConfig(filename=path, level=logging.DEBUG)
        self.logger = logging.getLogger('storj.downstream_farmer')

    def prepare_chunk_dir(self):
        try:
            if (not os.path.isdir(self.chunk_dir)):
                self.logger.debug('Creating directory {0}'.format(
                    os.path.abspath(self.chunk_dir)))
                os.mkdir(self.chunk_dir)
        except:
            raise DownstreamError(
                'Chunk directory could not be created: {0}'.
                format(sys.exc_info()[1]))

    def load_number(self, args):
        """Loads the number of challenges from the command line
        """
        if args.number is not None and args.number < 1:
            raise DownstreamError(
                'Must specify a positive number of challenges.')

        self.number = args.number

    def load_size(self, args):
        """Loads the total farming size from the command line
        """
        if args.size < 1:
            raise DownstreamError('Must specify a positive size to farm.')

        self.size = args.size

    def load_url_and_check(self, args):
        """Loads the target node url from the command line, or from the last
        known node, or the default.  Also checks connectivity to the node.
        """
        if (args.node_url is None):
            if ('last_node' in self.state):
                url = self.state['last_node']
            else:
                url = 'https://live.driveshare.org:8443'
        else:
            url = args.node_url

        self.url = url.strip('/')
        self.logger.info('Using url {0}'.format(self.url))
        self.stats.set('node_url', self.url)

        self.check_connectivity()

        self.state['last_node'] = self.url

    def load_token(self, args):
        """Either loads a saved token from history, from command line
        or, sets token to None if a new token is needed
        """
        saved_token = self.state.get('nodes', dict()).\
            get(self.url, dict()).get('token', None)

        if (args.token is not None):
            self.token = args.token
        else:
            self.token = saved_token

        if (args.forcenew):
            if (self.token is not None):
                self.logger.info('Not using token {0} since '
                                 'forcenew was specified.'.format(self.token))
                self.token = None

    def load_address(self, args):
        """Loads SJCX address either from history, command line, or from
        identities file
        """
        saved_address = self.state.get('nodes', dict()).\
            get(self.url, dict()).get('address', None)

        if (args.address is not None):
            self.address = args.address
            if (self.address != saved_address):
                self.logger.info('New address specified, obtaining new token.')
                self.token = None
        else:
            self.address = saved_address

        if (self.address is None):
            # no address specified on command line or in history with this
            # node, let's get one from the identities file if we can!
            if (len(self.identities) > 0):
                # we have at least one identity...
                # just take the first one
                self.address = next(iter(self.identities))

    def load_signature(self, args):
        """Loads a signature from the identities file for the address
        we are going to use.  If one is not specified, throws an error.
        """
        if (self.address in self.identities):
            # get the signatures associated with the identity
            if ('message' not in self.identities[self.address] or
                    'signature' not in self.identities[self.address]):
                raise DownstreamError(
                    'The file format for the identity file '
                    '{0} should be a JSON formatted dictionary like the '
                    'following:\n'
                    '   {{\n'
                    '      "your sjcx address": {{\n'
                    '         "message": "your message here",\n'
                    '         "signature":  "base64 signature from bitcoin '
                    'wallet or counterwallet",\n'
                    '      }}\n'
                    '   }}'.format(self.identity_path))
            self.message = self.identities[self.address]['message']
            self.signature = self.identities[self.address]['signature']
            if (not siggy.verify_signature(self.message,
                                           self.signature,
                                           self.address)):
                raise DownstreamError(
                    'Signature provided does not match address being used. '
                    'Check your formatting, your SJCX address, and try again.')
        else:
            # the address being used does not have any associated signatures
            # we will attempt to connect without them
            self.message = ''
            self.signature = ''

    def check_connectivity(self):
        """ Check to see if we even get a connection to the server.
        https://stackoverflow.com/questions/3764291/checking-network-connection
        """
        try:
            six.moves.urllib.request.urlopen(self.url, timeout=5)
        except six.moves.urllib.error.URLError:
            raise DownstreamError("Could not connect to server.")

    def called_every_second(self):
        uptime = self.client.uptime()
        self.stats.set(
            'uptime',
            datetime.timedelta(days=uptime.days, seconds=uptime.seconds))

    def run(self, reconnect=False):
        self.logger.info('Farmer started')
        self.client = DownstreamClient(
            self.url, self.token, self.address,
            self.size, self.message, self.signature,
            self, self.chunk_dir)

        self.client.set_cert_path(self.cert_path)
        self.client.set_verify_cert(self.verify_cert)

        try:
            self.client.connect()
        except DownstreamError as ex:
            if (str(ex) == 'Unable to connect: Nonexistent token.'):
                # token didn't exist on the server... clear token
                # and try again
                self.logger.warn('Given token did not exist on remote server. '
                                 'Attempting to obtain a new token.')
                self.client.token = None
                self.client.connect()
            else:
                raise

        # connection successful, save our state, then begin farming
        self.state.setdefault('nodes', dict())[self.client.server] = {
            'token': self.client.token,
            'address': self.client.address
        }

        save(self.history_path, self.state)

        self.client.run_async(reconnect, self.number)

        self.wait_for_shutdown()
