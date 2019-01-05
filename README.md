# Monero binary RPC client in Python

There have been a few times people have asked about calling a Monero daemon's
RPC **binary** methods from python/javascript/etc. Documentation is slim as
these binary methods are rather niche / special purpose.

This module implements the binary format used (EPEE Portable Storage) and
exposes an easy to use class for calling the binary interface RPC methods.

## Project status

Alpha

### Dependencies

- requests

### Usage

See [demo.py](./demo.py) for example usage.

## License

Please see the [LICENSE](./LICENSE) file.

[//]: # ( vim: set tw=80: )
