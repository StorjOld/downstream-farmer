downstream-farmer
=================

[![Build Status](https://travis-ci.org/Storj/downstream-farmer.svg?branch=master)](https://travis-ci.org/Storj/downstream-farmer)  [![Coverage Status](https://img.shields.io/coveralls/Storj/downstream-farmer.svg)](https://coveralls.io/r/Storj/downstream-farmer?branch=master)


## What is this?

`downstream-farmer` talks to [downstream-node](https://github.com/Storj/downstream-node).  In order to use it, you'll need a node up and running.  `downstream-node` requires MySQL and a working config, but *this app*, `downstream-farmer`, will require python-dev and libcrypto++-dev to install from source.

*Note*: If you are building on OSX, you can install crypto++ using homebrew: `$ brew install cryptopp`.

```
$ sudo apt-get install python-dev libcrypto++-dev git python-pip
$ git clone https://github.com/Storj/downstream-farmer.git
$ cd downstream-farmer
$ pip install -r requirements.txt .
```

To connect to our test node, you must have a whitelisted address and provide signed verification of ownership of that address.

There are a couple of ways to do this.  If you have your private keys in a local bitcoin wallet such as the mainline Bitcoin Client, Multibit, Armory, or Electrum, sign a message of your choice with your SJCX address that has a crowdsale balance of at least 10,000 SJCX.  Then make sure the message and signature are included in your `identities.json` file.

For example, on Counterwallet, click on Address Actions, and then Sign Message.  Type a message of your choice, and click Sign.  Then copy and paste the message and signature into the `identities.json` file in the `data/` directory.  For example:

```json
{
"19qVgG8C6eXwKMMyvVegsi3xCsKyk3Z3jV": {
 "message": "test message",
 "signature": "HyzVUenXXo4pa+kgm1vS8PNJM83eIXFC5r0q86FGbqFcdla6rcw72/ciXiEPfjli3ENfwWuESHhv6K9esI0dl5I="
}
```

Ensure that any whitespace in the message is included in the JSON string and that it is enclosed with double quotes.  Then, you can connect to our test node by running:

```
$ downstream
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


