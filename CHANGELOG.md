# downstream-farmer Changelog

### v0.1.7

* [BUGFIX] Fixed a few bugs where contract would not be removed if it was not proved in time
* [ENHANCEMENT] Added some optimizations, and now using heartbeat v0.1.9.

### v0.1.6

* [ENHANCEMENT] Added --print-log option to print logging to console.
* [ENHANCEMENT] Multiple contracts handled per request.
* [ENHANCEMENT] Added stats console and moved output to logger

### v0.1.5

* [ENHANCEMENT] Restructured farmer to include multithreading: multiple contract pools for answering contracts, and a contract management thread for maintaining the desired total contract size
* [ENHANCEMENT] Modified farmer to write chunks to disk in order to do some limited verification of dedicated hard disk capacity.

### v0.1.4

* [REBASE] Removed 32MB test file from far back in the history. Recommended to re-clone the repository.
* [ENHANCEMENT] Added --no-ssl-verify tag to prevent verification of ssl certificates

### v0.1.3

* [ENHANCEMENT] Switched to changelog methodology
* [ENHAMCEMENT] Added ability to specify a signature for submission to server for verification of ownership of address

### v0.1.2

* Alpha release with some good test functionality

### v0.1-alpha

* Initial alpha release