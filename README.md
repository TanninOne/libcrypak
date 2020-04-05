# Description

The CryEngine uses .pak files to store assets. These are regular .zip files but some games use an encryption on top, creating
a new file format.

This library handles decryption, either decrypting the entire file, generating an unencrypted zip file, or extracting individual files.
It does not do decompression so everything you get out of this library is still zip compressed.

The decryption key is different between games and may be changed between updates, it is not provided in this repository.

# Building

- clone this repository
- cd into your clone
- mkdir build && cd build
- cmake .. [-G <pick a generator>]
- cmake --build . [--config Release]

# Acknowledgments

This is built using a couple of libraries, thanks go out to their developers and maintainers:

- libtomcrypt (https://github.com/libtom/libtomcrypt/)
- libtommath (https://github.com/libtom/libtommath/)
- The {fmt} library (https://github.com/fmtlib/fmt)
