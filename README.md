downstream-farmer
=================

Master: [![Build Status](https://travis-ci.org/Storj/downstream-farmer.svg?branch=master)](https://travis-ci.org/Storj/downstream-farmer)  [![Coverage Status](https://img.shields.io/coveralls/Storj/downstream-farmer.svg)](https://coveralls.io/r/Storj/downstream-farmer?branch=master)
Devel: [![Build Status](https://travis-ci.org/Storj/downstream-farmer.svg?branch=devel)](https://travis-ci.org/Storj/downstream-farmer) [![Coverage Status](https://img.shields.io/coveralls/Storj/downstream-farmer.svg)](https://coveralls.io/r/Storj/downstream-farmer?branch=devel)

## What is this I don't even?

`downstream-farmer` talks to [downstream-node](https://github.com/Storj/downstream-node).  In order to use it, you'll need a node up and running.  `downstream-node` requires MySQL and a working config, but *this app*, `downstream-farmer`, installs its own dependencies.

```
$ pip install --process-dependency-links git+https://github.com/Storj/downstream-farmer.git
```

```
$ downstream --verify-ownership tests/thirty-two_meg.testfile 'http://address.to.farmer.node:5000'
```

**If this is at all confusing, we're doing it as a functional test in the travis.yml file, so watch it in action on Travis-CI.**


## Client Functions
Connects to a downstream compatible node. Should also generate a new account token.
    
    connect(url)

Sets the path where we store the file chunks. 

    store_path(path)

Queries the server for a file chunk, and then downloads it to a directory specified by config. Filename should be hash of the file.

    get_chunk(path)

Notifies the server that it is removing the file, then removes it from the directory.

    remove_chunk(hash)

Gets a list of challenges for us to fulfill. 

    get_challenges()

Uses the [heartbeat](https://github.com/Storj/heartbeat) library to find the corresponding hash to a challenge.  
    
    challenge(hash, challenge)

Returns the challenge to the server.

    answer(hash, hash_answer) 

## Prototype Functions
Because we need to implement proper sandboxing to prevent arbitrary code execution, all prototype clients will come with a 32 MB "genesis" file. This genesis file can be uniquely encrypted with the [file-encryptor](https://github.com/storj/file-encryptor) based on a secret passed by the node. This allows us to have a unique file without having to transfer any data.  

### Prototype Get Chunk Contract

Gives the farmer a data contract. Allow the client to download another chunk of data, including how often the server will check for the data (specified in seconds), and the initial challenge.

    GET /api/downstream/chunk/<token>

```json
{
    "secret": "d9fc3360c7",
    "file_hash": "05ecf7f9d218c631cc380527ac57f72798647824aa8839eb82045ed9fc3360c7", 
    "challenge": "0.012381234",
    "interval": 60
}
```

### Prototype Unique Chunk Generation
Using [file-encryptor](https://github.com/storj/file-encryptor) we can generate the necessary chunk. Make sure to check it against the file hash passed in the chunk contract. 

    gen_chunk(secret)
