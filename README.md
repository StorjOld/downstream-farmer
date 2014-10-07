downstream-farmer
=================

Master: [![Build Status](https://travis-ci.org/Storj/downstream-farmer.svg?branch=master)](https://travis-ci.org/Storj/downstream-farmer)  [![Coverage Status](https://img.shields.io/coveralls/Storj/downstream-farmer.svg)](https://coveralls.io/r/Storj/downstream-farmer?branch=master)
Devel: [![Build Status](https://travis-ci.org/Storj/downstream-farmer.svg?branch=devel)](https://travis-ci.org/Storj/downstream-farmer) [![Coverage Status](https://img.shields.io/coveralls/Storj/downstream-farmer.svg)](https://coveralls.io/r/Storj/downstream-farmer?branch=devel)


## What is this I don't even?

`downstream-farmer` talks to [downstream-node](https://github.com/Storj/downstream-node).  In order to use it, you'll need a node up and running.  `downstream-node` requires MySQL and a working config, but *this app*, `downstream-farmer`, installs its own dependencies.

```
$ git clone -b devel https://github.com/Storj/downstream-farmer.git
$ cd downstream-farmer
$ pip install -r requirements.txt .
```

Here is a sample command if you are already running [downstream-node](https://github.com/Storj/downstream-node) locally:
```
$ downstream 'http://address.to.farmer.node:5000'
```

This prototype performs three simple functions.  It connects to the specified downstream-node, it requests a chunk (which also gives it the first chunk challenge), and then it answers the chunk challenge.

**If this is at all confusing, we're doing it as a functional test in the travis.yml file, so watch it in action on Travis-CI.**


## Client Functions
Connects to a downstream compatible node. Should also generate a new account token and retrieves the heartbeat for the proof of storage.
    
    connect(url)

Queries the server for a file chunk, which in this prototype is simply a file seed for RandomIO to generate.

    get_chunk()

Answers the chunk contract that was retrieved with get_chunk().

    answer_challenge()

