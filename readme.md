cz-spas
=======

czspas (Small Portable Asynchronous Sockets) is minimalistic socket library inspired by Asio/Boost Asio, implemented in 1 single header file.

Features:

* Currently works on Windows and Linux.
	* Should be easy to port to any platform that supports BSD sockets.
* No external dependencies.
* Small codebase
* Asynchronous Asio-like API.
* Only IPv4 at the moment.

Intent
======

czspas was created with the intent of being used where a simple asynchronous TCP API is needed, but adding a dependency on something like Boost Asio (or Asio standalone) is overkill.

It was originally created for [https://bitbucket.org/ruifig/czrpc](https://bitbucket.org/ruifig/czrpc) to remove the dependency on Asio (although it is not yet being used in czrpc).

How to build
============

There is nothing to build. Just include ```spas.h``` (found in ```source\crazygaze\spas\```) in your project.

Visual Studio 2015 or higher is required on Windows. On Linux, any recent version of gcc/clang should work.

The **master** branch is the most stable one, and **dev** is where development happens.

Documentation
=============

Check the [Wiki](https://github.com/ruifig/czspas/wiki) for documentation.

Donations
=========

If you like czspas (or any of my other open source libraries), consider helping out with donations:

[![Paypal](https://www.paypalobjects.com/webstatic/en_US/i/btn/png/btn_donate_cc_147x47.png)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=YYWNU5LWRH8HS)

[![Patreon](https://cloud.githubusercontent.com/assets/8225057/5990484/70413560-a9ab-11e4-8942-1a63607c0b00.png)](https://www.patreon.com/RuiMVFigueira)


