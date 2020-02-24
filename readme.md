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



