downstream-farmer
=================

Master: [![Build Status](https://travis-ci.org/Storj/downstream-farmer.svg?branch=master)](https://travis-ci.org/Storj/downstream-farmer)  [![Coverage Status](https://img.shields.io/coveralls/Storj/downstream-farmer.svg)](https://coveralls.io/r/Storj/downstream-farmer?branch=master)
Devel: [![Build Status](https://travis-ci.org/Storj/downstream-farmer.svg?branch=devel)](https://travis-ci.org/Storj/downstream-farmer) [![Coverage Status](https://img.shields.io/coveralls/Storj/downstream-farmer.svg)](https://coveralls.io/r/Storj/downstream-farmer?branch=devel)


## What is this I don't even?

`downstream-farmer` talks to [downstream-node](https://github.com/Storj/downstream-node).  In order to use it, you'll need a node up and running.  `downstream-node` requires MySQL and a working config, but *this app*, `downstream-farmer`, will require python-dev and libcrypto++-dev to install from source.

```
$ sudo apt-get install python-dev libcrypto++-dev
$ git clone -b devel https://github.com/Storj/downstream-farmer.git
$ cd downstream-farmer
$ pip install -r requirements.txt .
```

And connect to our test node by running:
```
$ downstream
```

The usage is
```
usage: downstream [-h] [-V] [-n NUMBER] [-p PATH] [-s SIZE] [-a ADDRESS]
				  [-t TOKEN] [-f]
                  [node_url]

positional arguments:
  node_url              URL of the Downstream node

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  -n NUMBER, --number NUMBER
                        Number of challenges to perform.If unspecified,
                        perform challenges until killed.
  -p PATH, --path PATH  Path to save/load state from.
  -s SIZE, --size SIZE  Total size of contracts to obtain.
  -a ADDRESS, --address ADDRESS
                        SJCX address
  -t TOKEN, --token TOKEN
                        Farming token
  -f, --forcenew        Force obtaining a new token
```

This prototype performs three simple functions.  It connects to the specified node, it requests a chunk (which also gives it the first chunk challenge and information to recreate the test file), and then it answers the chunk challenge.

**If this is at all confusing, we're doing it as a functional test in the travis.yml file, so watch it in action on Travis-CI.**


