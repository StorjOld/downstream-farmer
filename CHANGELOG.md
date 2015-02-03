# downstream-farmer Changelog

### Master

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