GalaxyCash 0.8.4 BETA

Setup
---------------------
GalaxyCash Core is the original GalaxyCash client and it builds the backbone of the network. It downloads and, by default, stores the entire history of GalaxyCash transactions (which is currently more than 100 GBs); depending on the speed of your computer and network connection, the synchronization process can take anywhere from a few hours to a day or more.

To download GalaxyCash Core, visit [galaxycash.net](https://galaxycash.net/download).

Running
---------------------
The following are some helpful notes on how to run GalaxyCash on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/galaxycash-qt` (GUI) or
- `bin/galaxycashd` (headless)

### Windows

Unpack the files into a directory, and then run galaxycash-qt.exe.

### OS X

Drag GalaxyCash-Core to your applications folder, and then run GalaxyCash-Core.

### Need Help?

* See the documentation at the [Bitcoin Wiki](https://en.galaxycash.it/wiki/Main_Page)
for help and more information. GalaxyCash is very similar to galaxycash, so you can use their wiki.
* Ask for help on [#general](https://galaxycash.chat/) on galaxycash.chat.

Building
---------------------
The following are developer notes on how to build GalaxyCash on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [OS X Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [Gitian Building Guide](gitian-building.md)

Development
---------------------
The GalaxyCash repo's [root README](/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Release Notes](release-notes.md)
- [Release Process](release-process.md)
- [Source Code Documentation (External Link)](none-yet)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [Travis CI](travis-ci.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Shared Libraries](shared-libraries.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)

### Resources
* TODO: add some galaxycash resourses

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [ZMQ](zmq.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).
This product includes software developed by the OpenSSL Project for use in the [OpenSSL Toolkit](https://www.openssl.org/). This product includes
cryptographic software written by Eric Young ([eay@cryptsoft.com](mailto:eay@cryptsoft.com)), and UPnP software written by Thomas Bernard.
