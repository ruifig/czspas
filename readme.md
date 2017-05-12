cz-spas
=======

czspas (Small Portable Asynchronous Sockets) is minimalistic socket library inspired by Asio/Boost Asio, implemented in 1 single header file.

Features:

* Currently works on Windows and Linux, although if should be easy to port to any platform that supports BSD sockets.
* No external dependencies.
* Small codebase (~1500 lines at the time of writting)
* Asynchronous Asio-like API.
* Only IPv4 at the moment.

Intent
======

czspas was created with the intent of being used where a simple asynchronous TCP api needed, but adding a dependency on something like Asio/Boost Asio is overkill.

It was originally created for [https://bitbucket.org/ruifig/czrpc]() to remove the dependency on Asio (although it is not yet being used in czrpc).

Documentation
=============

The only documentation available at the moment are the unit tests themselves and any samples provided.

The API guarantees the following:

* Completion handlers will only be called from the thread running ```Service::run()```
	* This is the same as Asio
* Calls to ```Service::post``` and ```Service::stop``` are thread safe, but ```Service::run``` is NOT.
	* This it not the same as Asio. On Asio you can call ```io_service::run()``` from multiple threads.
	* This is an intentional design decision to keep czspas as simple as possible. It might change in the future to make ```Service``` fully thread safe.

The API expects the following from the user code:

* ```Socket``` and ```Acceptor``` instances are NOT thread safe.
	* This is the same as Asio.
	* Calls to any member functions should be posted with ```Service::post```.
* Is the responsability of the user code to manage the lifetime of objects used in the completion handlers (e.g: Sockets, Acceptor, buffers)
	* This is the same as Asio.
	* For example, a given ```Socket``` instance must stay alive while there are pending asynchronous operations using it.
	* A common solution to this lifetime problem is to put all the relevant objects and buffers in a class/struct and bind a shared_ptr to any completion handler that needs it. This effectively keeps the relevant objects alive for the duration of the asynchronous operation.

Donations
=========

[![Patreon](https://cloud.githubusercontent.com/assets/8225057/5990484/70413560-a9ab-11e4-8942-1a63607c0b00.png)](https://www.patreon.com/RuiMVFigueira)

