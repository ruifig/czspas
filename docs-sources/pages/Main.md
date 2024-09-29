# Main Page

czspas was inspired by the [Asio C++ Library](https://think-async.com/Asio/) circa 2016-2017, and thus a big part of the API is similar and provides a similar set of guarantees to what Asio provided back then.

czspas is **NOT** replacement for Asio. It offers a limited set of features compared to Asio, and that will always be the case.
The purpose is to be a small and portable asynchronous TCP sockets library that is easy to use.

If it doesn't provide the features you need, you should use Asio instead.

The source code is composed of two files (`.h` and `.cpp`), and requires a C++17 compiler.

## Overview

The entire relevant API resides inside the `cz::spas` namespace. The `cz::spas::detail` namespace contains implementation details that don't need to be used directly.
Any functions prefixed with `_` should not be used. They might be public to solve some design problem(s) or to be used by the tests, and should not be consider part of the API.

The API revolves around using just a few classes:

* [zstring_view](@ref cz::spas::zstring_view)
* [Error](@ref cz::spas::Error)
* [Service](@ref cz::spas::Service)
* I/O objects: 
    * [Acceptor](@ref cz::spas::Acceptor)
    * [Socket](@ref cz::spas::Socket)
    * [Resolver](@ref cz::spas::Resolver)

**zstring_view** is used throughout the API to represent a null-terminated string. The API uses this instead of `const char*` or `std::string_view` because:
	* It self-documents when a parameter can't be null.
	* It self-documents that it needs to be null-terminated. This is because internally some strings end up being passed to logging functions or OS functions that expect null-terminated strings.
	* It automatically converts from `const char*` or `std::string`, so it is transparent for those cases.
	* If an application tries to use `std::string_view`, those cases will not compile because `std::string_view` is not guaranteed to be null-terminated.

**Error** is used error reporting throughout the API.

**Service** is the hub that manages all asynchronous work.
You need at least 1 Service instance in your application.

In practical terms, you can think of the Service class as a work queue. Asynchronous handlers for any work items deemed completed are queued for execution through a Service instance and are executed from inside [Service::run](@ref cz::spas::Service::run).

**Acceptor** is used to accept incoming connections. Any asynchronous work initiated for a given Acceptor instance will get its handler executed through the owning Service instance when the user calls [Service::run](@ref cz::spas::Service::run)

**Socket** is used to send and receive data. Like **Acceptor**, handlers for any asynchronous work initiated for a Socket instance is executed through the owning Service instance.

**Resolver** is used to resolve endpoints. E.g, you give it a host name, and returns the ip to connect to that host.


## Guarantees and expectations

It provides the following guarantees:

* Asynchronous completion handlers will only be called from the thread currently calling [Service::run](@ref cz::spas::Service::run)
    * This is the same as Asio
* All asynchronous completion handlers are called exactly **ONCE**, provided the owning Service` is alive and its `run` method is called to execute those handlers.
    * This is the same as Asio
* When a I/O object is destroyed, any of its asynchronous operations that have not yet completed will complete with the error `Error::Code::Aborted`. 
    * This is the same as Asio
* Calls to `Service::post` and `Service::stop` are thread safe, but `Service::run` is NOT.
	* This it **NOT** the same as Asio. On Asio you can call `Service::run()` from multiple threads.
	* This is an intentional design decision to keep czspas as simple as possible. It might change in the future to make `Service` fully thread safe.

Also, similar to Asio, the API expects the following from the user code:

* I/O objects instances are NOT thread safe.
	* This is the same as Asio.
	* Be sure to use `Service::post` accordingly, instead of directly calling operations on the I/O objects. E.g, if thread A is the one running `Service::run`, and you want start some I/O operation from thread B, you should use `Service::post`.
* Is the responsibility of the user code to manage the lifetime of objects used in the completion handlers (e.g: Sockets, Acceptor, Resolvers, buffers)
	* This is the same as Asio.
	* For example, a given `Socket` instance must stay alive while there are pending asynchronous operations using it.
	* A common solution to this lifetime problem is to put all the relevant objects and buffers in a class/struct and bind a shared_ptr to any completion handler that needs it. This effectively keeps the relevant objects alive for the duration of the asynchronous operation. This is the pattern also recommended for Asio.

## Types of callbacks

All functions/methods that initiate asynchronous work take as a parameter a callback that is executed when the work in question is completed (successfully, in error, or aborted).

In order to make it easier to deal with compile errors due wrong handler signature, the API is not as heavily templated as Asio.
This is an intentional design.


* PostHandler: ```void ()```
	* Handler type for work explicitly queued with [Service::post](#service-post)
* ConnectHandler: ```void (const Error& ec)```
	* Handler type used for initiating connections. E.g: Used with [Acceptor::asyncAccept](#acceptor-accept) and [Socket::asyncConnect](#socket-asyncConnect)
	* **ec** : Tells if the operation completed successfully or not.
* TransferHandler: ```void (const Error& ec , size_t transfered)```
	* Handler type used for sending and receiving data. E.g: [asyncSend](#asyncsend) and [asyncReceive](#asyncreceive)
	* **ec** : Tells if the operation completed successfully or not.
	* **transfered** : How much data was sent (if it was a send operation), or received (if it was a receive operation).
