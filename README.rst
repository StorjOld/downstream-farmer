Downstream Farmer
=================

|Build Status| |Coverage Status|

What is this?
-------------

``downstream-farmer`` talks to
`downstream-node <https://github.com/Storj/downstream-node>`__. In order
to use it, you'll need a node up and running. ``downstream-node``
requires MySQL and a working config, but *this app*,
``downstream-farmer``, will require python-dev and libcrypto++-dev to
install from source.

You can install and use ``downstream-farmer`` on all major operating systems:

**Ubuntu** 

::

    $ sudo apt-get install python-dev libcrypto++-dev libgmp-dev git python-pip
    $ pip install --process-dependency-links downstream-farmer

It is recommended to run your `pip install` inside a Python virtual environment to prevent potential conflicts with your system Python and packages.

**OSX**

::

    $ brew tap storj/storj
    $ brew install downstream-farmer

After adding the ``storj/storj`` tap, you can use ``brew info downstream-farmer`` at any time to see usage information.

**Windows**

Use the binaries available `here <https://github.com/Storj/downstream-farmer/releases>`_.

To connect to our test node, you must have a whitelisted address and
provide signed verification of ownership of that address.

There are a couple of ways to do this. If you have your private keys in
a local bitcoin wallet such as the mainline Bitcoin Client, Multibit,
Armory, or Electrum, sign a message of your choice with your SJCX
address that has a crowdsale balance of at least 10,000 SJCX. Then make
sure the message and signature are included in your ``identities.json``
file.

For example, on Counterwallet, click on Address Actions, and then Sign
Message. Type a message of your choice, and click Sign. Then copy and
paste the message and signature into the ``identities.json`` file in the
``data/`` directory, replacing the example identity. For example:

.. code:: json

    {
      "19qVgG8C6eXwKMMyvVegsi3xCsKyk3Z3jV": {
         "message": "test message",
         "signature": "HyzVUenXXo4pa+kgm1vS8PNJM83eIXFC5r0q86FGbqFcdla6rcw72/ciXiEPfjli3ENfwWuESHhv6K9esI0dl5I="
      }
    }

Ensure that any whitespace in the message is included in the JSON string
and that it is enclosed with double quotes. Then, you should be able to
connect to our test node by running (assuming your SJCX address is in
the crowdsale whitelist):

::

    $ downstream

The usage of the program is:

::

	usage: downstream [-h] [-V] [-n NUMBER] [-p HISTORY] [-s SIZE] [-a ADDRESS]
					  [-t TOKEN] [-f] [-i IDENTITY] [-d DATA_DIRECTORY]
					  [--ssl-no-verify] [--log-path LOG_PATH] [--quiet]
					  [--print-log]
					  [node_url]

	positional arguments:
	  node_url              URL of the downstream node to connect to. The default
							node is https://live.driveshare.org:8443

	optional arguments:
	  -h, --help            show this help message and exit
	  -V, --version         show program's version number and exit
	  -n NUMBER, --number NUMBER
							Number of challenges to perform. If unspecified,
							perform challenges until killed.
	  -p HISTORY, --history HISTORY
							Path to save/load history from. The history file saves
							your farming tokens for each node you connect to. The
							default path is data\history.json.
	  -s SIZE, --size SIZE  Total size of contracts to obtain in bytes. Default is
							33554432 bytes
	  -a ADDRESS, --address ADDRESS
							SJCX address for farming. You can specify this if you
							have multiple identities and would like to farm under
							one of them. Otherwise by default, an address from
							your identity file (data\identities.json) will be
							used.
	  -t TOKEN, --token TOKEN
							Farming token to use. If you already have a farming
							token, you can reconnect to the node with it by
							specifying it here. By default a new token will be
							obtained. Any tokens obtained will be saved in the
							history JSON file.
	  -f, --forcenew        Force obtaining a new token. If the node has been
							reset and your token has been deleted, it may be
							necessary to force your farmer to obtain a new token.
	  -i IDENTITY, --identity IDENTITY
							Specify an identity file to  provide a signature to
							prove ownership of your SJCX address. The default path
							is data\identities.json.  The file format should be a
							JSON dictionary like the following:
							{
							   "your sjcx address": {
								  "message": "your message here",
								  "signature": "base64 signature from bitcoin\
												 wallet or counterwallet",
							   }
							}
							If an identity is specified in this file, it will be
							used for connecting to any new nodes.
	  -d DATA_DIRECTORY, --data-directory DATA_DIRECTORY
							Data directory to place file chunks. By default
							data\chunks
	  --ssl-no-verify       Do not verify ssl certificates.
	  --log-path LOG_PATH   Path to the log file. Default is: farmer.log
	  --quiet               Do not show the status console.
	  --print-log           Print log to screen instead of status console.

This prototype performs three simple functions. It connects to the
specified node, it requests a chunk (which also gives it the first chunk
challenge and information to recreate the test file), and then it
answers the chunk challenge.

**If this is at all confusing, we're doing it as a functional test in
the travis.yml file, so watch it in action on Travis-CI.**

.. |Build Status| image:: https://travis-ci.org/Storj/downstream-farmer.svg?branch=master
   :target: https://travis-ci.org/Storj/downstream-farmer
.. |Coverage Status| image:: https://img.shields.io/coveralls/Storj/downstream-farmer.svg
   :target: https://coveralls.io/r/Storj/downstream-farmer?branch=master
