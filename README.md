downstream-farmer
=================

Master: [![Build Status](https://travis-ci.org/Storj/downstream-farmer.svg?branch=master)](https://travis-ci.org/Storj/downstream-farmer)  [![Coverage Status](https://img.shields.io/coveralls/Storj/downstream-farmer.svg)](https://coveralls.io/r/Storj/downstream-farmer?branch=master)
Devel: [![Build Status](https://travis-ci.org/Storj/downstream-farmer.svg?branch=devel)](https://travis-ci.org/Storj/downstream-farmer) [![Coverage Status](https://img.shields.io/coveralls/Storj/downstream-farmer.svg)](https://coveralls.io/r/Storj/downstream-farmer?branch=devel)


## What is this I don't even?

`downstream-farmer` talks to [downstream-node](https://github.com/Storj/downstream-node).  In order to use it, you'll need a node up and running.  `downstream-node` requires MySQL and a working config, but *this app*, `downstream-farmer`, will require python-dev and libcrypto++-dev to install from source.

```
$ sudo apt-get install python-dev libcrypto++-dev git python-pip
$ git clone -b devel https://github.com/Storj/downstream-farmer.git
$ cd downstream-farmer
$ pip install -r requirements.txt .
```

And connect to our test node by running:
```
$ downstream -a YOUR_SJCX_ADDRESS
```

The usage of the program is:

```
usage: downstream [-h] [-V] [-n NUMBER] [-p PATH] [-s SIZE] [-a ADDRESS]
                  [-t TOKEN] [-f]
                  [node_url]

positional arguments:
  node_url              URL of the downstream node to connect to

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  -n NUMBER, --number NUMBER
                        Number of challenges to perform. If unspecified,
                        perform challenges until killed.
  -p PATH, --path PATH  Path to save/load state from. The state file saves
                        your last connected node, your farming tokens, your
                        SJCX address, and other data. The default is
                        data\state.json
  -s SIZE, --size SIZE  Total size of contracts to obtain in bytes. Default is
                        100 bytes
  -a ADDRESS, --address ADDRESS
                        SJCX address for farming. You only need to specify
                        this the first time you connect after that, your
                        address is saved by the node under your farming token
  -t TOKEN, --token TOKEN
                        Farming token to use. If you already have a farming
                        token, you can reconnect to the node with it by
                        specifying it here. By default a new token will be
                        obtained if you specify an SJCX address to use.
  -f, --forcenew        Force obtaining a new token. If the node has been
                        reset and your token has been deleted, it may be
                        necessary to force your farmer to obtain a new token.
```

This prototype performs three simple functions.  It connects to the specified node, it requests a chunk (which also gives it the first chunk challenge and information to recreate the test file), and then it answers the chunk challenge.

**If this is at all confusing, we're doing it as a functional test in the travis.yml file, so watch it in action on Travis-CI.**


