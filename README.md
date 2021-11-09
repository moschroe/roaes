roaes
-----

### Library

Library implementing the openaes standard used by the [Team Win Recovery Project (TWRP)][1], as of 2018-08-24.

There are both implementations for reading (decrypting) and writing (encrypting) data. The intention is to make encrypted TWRP backups accessible or even facilitate re-compression with a different/more modern algorithm.

#### Beware

**All cryptographic code is re-used from libraries of the wider ecosystem. No assessment as to their quality or suitability has been made beyond testing basic compliance with sample files!**

### Binary

The executable `roaes` will decrypt and encrypt the openaes format. It uses very simple command line parsing. Running the command without any parameter will print its usage information.

```text
USAGE: roaes enc|dev <key>

decrypts files encrypted in CBC mode with the TWRP-flavoured oaes binary
reads stdin and writes to stdout, expects encryption key as single argument
```

Data is read from standard input and written to standard output. No file handles are opened at all. To process data, use appropriate shell mechanisms like `roaes enc somekey < plaintext.file > ciphertext.file`.

Setting the environment variable `RUST_LOG` to one of `trace`, `debug`, `info`, `warn` or `error` might reveal information about internal state (though _neither_ plaintext, ciphertext nor key material).

[1]: <https://github.com/TeamWin/Team-Win-Recovery-Project/tree/58f2132bc3954fc704787d477500a209eedb8e29/openaes>