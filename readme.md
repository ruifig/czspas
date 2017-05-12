cz-spas
=======

czspas (Small Portable Asynchronous Sockets) is minimalistic socket library inspired by Asio/Boost Asio, implemented in 1 single header file.

Supported features:

* Currently works on Windows and Linux, although if should be easy to port to any platform that supports BSD sockets.
* No external dependencies.
* Asynchronous Asio-like API.
* Only IPv4 at the moment.

Intent
======

czspas was created with the intent of being used where a simple asynchronous TCP api needed, but adding a dependency on something like Asio/Boost Asio is overkill.

It was originally created for [https://bitbucket.org/ruifig/czrpc]() to remove the dependency on Asio (although not integrated in czrpc yet).

Documentation
=============


Donations
=========

[![Patreon](https://cloud.githubusercontent.com/assets/8225057/5990484/70413560-a9ab-11e4-8942-1a63607c0b00.png)](https://www.patreon.com/RuiMVFigueira)

