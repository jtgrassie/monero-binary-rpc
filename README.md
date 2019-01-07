# Monero binary RPC client in Python

There have been a few times people have asked about calling a Monero daemon's
RPC **binary** methods from python/javascript/etc. Documentation is slim as
these binary methods are rather niche / special purpose.

This module implements the binary format used (epee portable storage) and
exposes an easy to use class for calling the binary interface RPC methods.

## Project status

All the Monero binary RPC commands are now implemented.

### Dependencies

- requests

### Usage

See [demo.py](./demo.py) for example usage.

### Portable Storage documentation

As there is no formal documentation on the binary format used, I have created a
reference [document](./reference/portable-storage.md).

## License

Please see the [LICENSE](./LICENSE) file.

[//]: # ( vim: set tw=80: )
