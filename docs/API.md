<a id="overall-design"></a>
## Overall design

Use of czspas revolves around using just a couple of classes:

* [Service](#service)
* [Acceptor](#acceptor)
* [Socket](#socket)
* [Error](#error)

**Error** is used to report error throughout the API.

**Service** is the hub that manages all asynchronous work.
You need at least 1 Service instance in your application.

In practical terms, you can think of the Service class as a work queue. Asynchronous handlers for any work items deemed completed are queued for execution through a Service instance and are executed from inside **Service::run()**.

**Acceptor** is used to accept incoming connections. Any asynchronous work initiated for a given Acceptor instance will get its handler executed through the owning Service instance when the user calls **Service::run**

**Socket** is used to send and receive data. Like **Acceptor**, handlers for any asynchronous work initiated for a Socket instance is executed through the owning Service instance.

***Structure***

The entire relevant API resides in the ```cz::spas``` namespace. The ```cz::spas::detail``` namespace contains implementation details, and nothing in that namespace needs to be used directly.

Functions prefixed with "_" should not be used. Those are accessible to make coding the unit tests easier.

## Guarantees and expectations

Since czspas is inspired by Asio, and the API is somewhat similar, it provides a similar set of guarantees.

The API guarantees the following:

* Completion handlers will only be called from the thread running ```Service::run()```
	* This is the same as Asio
* Calls to ```Service::post``` and ```Service::stop``` are thread safe, but ```Service::run``` is NOT.
	* This it not the same as Asio. On Asio you can call ```io_service::run()``` from multiple threads.
	* This is an intentional design decision to keep czspas as simple as possible. It might change in the future to make ```Service``` fully thread safe.

Also, similar to Asio, the API expects the following from the user code:

* ```Socket``` and ```Acceptor``` instances are NOT thread safe.
	* This is the same as Asio.
	* Calls to any member functions should be posted with ```Service::post```.
* Is the responsibility of the user code to manage the lifetime of objects used in the completion handlers (e.g: Sockets, Acceptor, buffers)
	* This is the same as Asio.
	* For example, a given ```Socket``` instance must stay alive while there are pending asynchronous operations using it.
	* A common solution to this lifetime problem is to put all the relevant objects and buffers in a class/struct and bind a shared_ptr to any completion handler that needs it. This effectively keeps the relevant objects alive for the duration of the asynchronous operation.

## Type of callbacks

All functions/methods that initiate asynchronous work take as a parameter a callback that is executed when the work in question is completed (successfully, in error, or cancelled).

In order to make it easier to deal with compile errors due wrong handler signature, the API classifies handlers in 3 types, instead of using template parameters in most situations.

* PostHandler: ```void ()```
	* Handler type for work explicitly queued with [Service::post](#service-post)
* ConnectHandler: ```void (const Error& ec)```
	* Handler type used for initiating connections. E.g: Used with [Acceptor::asyncAccept](#acceptor-accept) and [Socket::asyncConnect](#socket-asyncConnect)
	* **ec** : Tells if the operation completed successfully or not.
* TransferHandler: ```void (const Error& ec , size_t transfered)```
	* Handler type used for sending and receiving data. E.g: [asyncSend](#asyncsend) and [asyncReceive](#asyncreceive)
	* **ec** : Tells if the operation completed successfully or not.
	* **transfered** : How much data was sent (if it was a send operation), or received (if it was a receive operation).


<a id="error"></a>
## Error

Instances of this class are used to indicate success or errors.

***Thread safety***

*Distinct objects*: Safe

*Shared objects*: Unsafe

### <a name="error-constructor">Constructor</a>

```cpp
Error(Code c = Code::Success); // (1)
Error(Code c, const char* msg); // (2)
Error(Code c, const std::string& msg) // (3)
```

***Parameters***

* **c** : Error code
* **msg** : Custom error message

***Remarks***

In most situations you will probably only need to use constructor (1).

### <a name="error-msg">msg</a>

```cpp
const char* msg() const;
```

***Return value***

Message associated with the error. In some situations it might be as simple as e.g "ConnectionClosed". Availability of a detailed error message depends where in the implementation the error occurred.

### <a name="error-setmsg">setMsg</a>

```cpp
void setMsg(const char* msg);
```

Sets a custom error message.

This can be useful if czspas gives you an error and you want to set a more detailed error description before passing it to other parts of the code.

### <a name="error-operator-bool">operator bool()</a>

***Return value***

Returns *true* if this Error instance represent an error, or *false* if represent success.

Note that this is intentionally reversed compared to other APIs. For example, say you have a function *bool doWork()*. Common sense says it returns *true* for success and *false* for errors. But since with czspas an error has its own class, it makes more sense to do something as:

```cpp
Error ec = socket.connect("127.0.0.1", 9000);

if (ec) // As-in  "if error then"
{
	// An error occurred
	printf("Failed to connect: %s\n", ec.msg());
	// ... handle the error
}
```

### <a name="error-code">code</a>

```cpp
Code code;
```

Error code.

The following error codes are available:

* **Code::Success** : The operation completed successfully
* **Code::Cancelled** : The operation cancelled by the user.
* **Code::Timeout** : The user specified a timeout for the operation, and operation failed to complete within that time frame.
* **Code::ConnectionClosed** : The connection was closed, either explicitly or not (e.g: The peer closed the connection)
* **Code::InvalidSocket** : An operation was attempted with an invalid socket.
* **Code::Other** : Any other error. The *msg* method should provide more information about the nature of the error.

Note that the list of possible error codes is intentionally short, since in most situations you don't care what the error was. You just want to know if there was an error. This design choice might change in the future.

## Service

***Thread safety***

*Distinct objects*: Safe

*Shared objects*: Safe, except *Service::run* like explained in [Guarantees and expectations](#guarantees-and-expectations).

### <a name="service-run">Service::run</a>

```cpp
void run();
```

Run the processing loop. This blocks until a call to *stop()* is made.

The asynchronous work handlers are only ever executed from inside this function.

Subsequent calls to this function will return immediately unless there is a prior call to *reset()*.

***Remarks***

* This function is not thread safe
* Since your asynchronous handlers are executed from inside this function, be careful not to call it from your handlers, since it is not reentrant.

### <a name="service-post">Service::post</a>

```cpp
void post(PostHandler&& h);
```

Request the Service to execute the given handler, but not from inside this function.
The handler is queued for execution from a thread calling *run()*, and this function returns immediately.

### <a name="service-stop">Service::stop</a>

```cpp
void stop();
```

Stop the Service processing loop.

Subsequent calls to *run()* will return immediately until *reset()* is called

### <a name="service-isstopped">Service::isStopped</a>

```cpp
bool isStopped() const;
```

Determine if the Service has been stopped through an explicit call to *stop()*.

### <a name="service-reset">Service::reset</a>

```cpp
bool reset() const;
```

Reset the Service in preparation for a subsequent *run()* invocation.

## Acceptor

Accepts incoming connections

***Thread safety***

*Distinct objects*: Safe

*Shared objects*: Unsafe. See [Guarantees and expectations](#guarantees-and-expectations).

### <a name="acceptor-constructor">Constructor</a>

```cpp
Acceptor(Service& service);
```

***Parameters***

* **service** : The Service object that will be managing all the work for this Acceptor.
All asynchronous work handlers for this Acceptor will be executed through this Service's *run()* function.

### <a name="acceptor-listen">Acceptor::listen</a>

```cpp
Error listen(int port); // (1)
Error listenEx(const char* bindIP, int port, int backlog, bool reuseAddr); // (2)
```

Start listening for new connections.
After calling this function, new connections can be acquired with *accept()* or *asyncAccept()*.

***Parameters***

* **bindIP** : Address to bind to
	* A *nullptr* or *0.0.0.0* will listen for incoming connections on any available network interface.
	* An explicit value (e.g: *127.0.0.1*) will only listen for connections to that specific network interface (aka: localhost).
	* An example on what situation this can be useful is for example if are using czspas for interprocess communications (processes on the same machine), and so you only want to accept connections that originated locally (A process on the same machine).
* **port** : Port to listen on.
	* A value of *0* will let the OS pick a free port. 
* **backlog** : The maximum length of the queue of pending connections.
	* This is mostly an hint to the OS. Don't expect this to work the same way on every OS
* **reuseAddr** : If true it will set the *SO_REUSEADDR* option on the socket.
	* To understand the implications of this on a specific OS, read [https://stackoverflow.com/questions/14388706/socket-options-so-reuseaddr-and-so-reuseport-how-do-they-differ-do-they-mean-t](https://stackoverflow.com/questions/14388706/socket-options-so-reuseaddr-and-so-reuseport-how-do-they-differ-do-they-mean-t)

***Return value***

Use the returned *Error* object to check for errors

***Remarks*** 

(1) This version of send is probably enough for most cases. It assumes the most common parameters for a server application, such as:

* It binds to address *0.0.0.0* (listen on any available network interface)
* Uses the default backlog (Maximum allowed)
* On Linux, it enables *SO_REUSEADDR*

(2) allows full control over all available parameters

### <a name="acceptor-accept">Acceptor::accept</a>

```cpp
Error accept(Socket& sock, int timeoutMs=-1);
```

Accepts a new connection. You need to call *listen* before calling this function.

***Parameters***

* **sock** : Socket where to put the incoming connection.
	* This needs to be an unconnected socket. As-in, you didn't perform any operations on it yet. Behaviour is undefined otherwise.
* **timeoutMs** : Timeout for the operation, in milliseconds.
	* The default value (-1) means no timeout should be used;

***Return Value***

Use the returned *Error* object to check for errors

### <a name="acceptor-asyncaccept">Acceptor::asyncAccept</a>

```cpp
void asyncAccept(Socket& sock, ConnectHandler&& h); // (1)
void asyncAccept(Socket& sock, timeoutMs, ConnectHandler&& h); // (2)
```

Starts an asynchronous accept. Once a new connection is accepted (or an error occurs), the handler will be executed from a thread running *thread::run*.

***Parameters***

* **sock** : Socket where to put the incoming connection.
	* This needs to be an unconnected socket. As-in, you didn't perform any operations on it yet. Behaviour is undefined otherwise.
* **timeoutMs** : Timeout for the operation, in milliseconds.
* **h** : Completion handler for the operation.

***Remarks***

(1) Assumes a timeout of -1 (no timeout)

### <a name="acceptor-cancel">Acceptor::cancel</a>

```cpp
void cancel();
```

Cancels all outstanding asynchronous operations. The handlers for the cancelled operations will be passed the *Error::Code::Cancelled* error.

### <a name="acceptor-getservice">Acceptor::getService</a>

```cpp
Service& getService();
```

***Return value***

The Service associated with this object.

### <a name="acceptor-setlinger">Acceptor::setLinger</a>

```cpp
void setLinger(bool enabled, unsigned short timeoutSeconds);
```

Controls the SO_LINGER socket options.

***Remarks***

You should know what SO_LINGER does before trying to use this function.

### <a name="acceptor-getlocaladdr">Acceptor::getLocalAddr</a>

```cpp
const std::pair<std::string, int>& getLocalAddr() const;
```

***Return value***

The address the Acceptor is listening on (ip and port).

### <a name="acceptor-gethandle">Acceptor::getHandle</a>

```cpp
SocketHandle getHandle();
```

***Return value***

The native socket handle.

***Remarks***

This function is provided just as convenience if you wish to do something czspas doesn't support. BE CAREFUL with what you do with the handle.

## Socket

***Thread safety***

*Distinct objects*: Safe

*Shared objects*: Unsafe. See [Guarantees and expectations](#guarantees-and-expectations).

*Socket* is what you actually use to send and receive data.

***Remarks***

* The available methods for sending and receiving data do not necessarily send/receive all the requested data. They complete as soon the OS says some data was sent/received.
	* To send/receive a buffer in its entirety, use the composed operations (e.g: *cz::spas::send*). Composed operations make multiple calls to the equivalent Socket operations until all the data is sent/received or an error occurs.
* Only one send operation and one receive operation can be active at one point.
	* In other words, do not make a call to any send (synchronous or asynchronous) while there is another send operation in progress. Same for receive operations.

### <a name="socket-constructor">Constructor</a>

```cpp
Socket(Service& service);
```
***Parameters***

* **service** : The Service object that will be managing all the work for this Socket.
All asynchronous work handlers for this Socket will be executed through this Service's *run()* function.

### <a name="socket-connect">Socket::connect</a>

```cpp
Error connect(const char* ip, int port);
```
***Parameters***

* **ip** : The ip to connect to.
* **port** : Port to connect to

***Return value***

The operation result (success or an error)

### <a name="socket-asyncconnect">Socket::asyncConnect</a>

```cpp
void asyncConnect(const char* ip, int port, ConnectHandler&& h); // (1)
void asyncConnect(const char* ip, int port, int timeoutMs, ConnectHandler&& h); // (2)
```

Starts an asynchronous connect operation

***Parameters***

* **ip** : The ip to connect to
* **port** : Port to connect to
* **timeoutMs** : The timeout for the operation in milliseconds.
* **h** : The completion handler for the operation.

***Remarks***

(1) It uses a timeout of *-1* (no timeout)

### <a name="socket-sendsome">Socket::sendSome</a>

```cpp
size_t sendSome(const char* buf, size_t len, Error& ec); // (1)
size_t sendSome(const char* buf, size_t len, int timeoutMs, Error& ec); // (2)
```
Synchronously sends data. It will block until some data is sent or an error occurs.

***Parameters***

* **buf** : Pointer to the data to send.
* **len** : Size of the data to send (in bytes).
* **timeoutMs** : The timeout for the operation in milliseconds.
* **ec** : Where you'll get the operation result (success or an error)

***Return value***

How many bytes were sent. This can be smaller than *len*.

Note that this doesn't necessarily means the peer received the data. Just means the data was passed to the Operating System's transport layer.

***Remarks***

* (1) It uses a timeout of *-1* (no timeout)
* This operation might send less data than *len*. Use the free function *send* to send a buffer in is entirety.

### <a name="socket-asyncsendsome">Socket::asyncSendSome</a>

```cpp
void asyncSendSome(const char* buf, size_t len, TransferHandler&& h); // (1)
void asyncSendSome(const char* buf, size_t len, int timeoutMs, TransferHandler&& h); // (2)
```

Starts an asynchronous send operation.

***Parameters***

* **buf** : Pointer to the data to send.
* **len** : Size of the data to send (in bytes).
* **timeoutMs** : The timeout for the operation in milliseconds.
* **h** : Completion handler for the operation.

***Remarks***

* (1) It uses a timeout of *-1* (no timeout)
* This operation might send less data than *len*. Use the free function *asyncSend* to send a buffer in is entirety.

### <a name="socket-receivesome">Socket::receiveSome</a>

```cpp
size_t receiveSome(char* buf, size_t len, Error& ec); // (1)
size_t receiveSome(char* buf, size_t len, int timeoutMs, Error& ec); // (2)
```

Synchronously receives data. It will block until some data is receive or an error occurs.

***Parameters***

* **buf** : Pointer to where the data received should be copied to.
* **len** : How much data to receive.
* **timeoutMs** : The timeout for the operation in milliseconds. If no data is received within this time (successfully or in error), it will return *Error::Code::Timeout*.
* **ec** : Where you'll get the operation result (success or an error)

***Return value***

How many bytes were sent. This can be smaller than *len*.

Note that this doesn't necessarily means the peer received the data. Just means the data was passed to the Operating System's transport layer.

***Remarks***

* (1) It uses a timeout of *-1* (no timeout)
* This operation might receive less data than *len*. Use the free function *receive* to receive a buffer in is entirety.

### <a name="socket-asyncreceivesome">Socket::asyncReceiveSome</a>

```cpp
void asyncReceiveSome(char* buf, size_t len, TransferHandler&& h); // (1)
void asyncReceiveSome(char* buf, size_t len, int timeoutMs, TransferHandler&& h); // (2)
```

Starts an asynchronous receive operation.

***Parameters***

* **buf** : Pointer to where the received data should be copied to.
* **len** : How much data to receive.
* **timeoutMs** : The timeout for the operation in milliseconds.
* **h** : Completion handler for the operation.

***Remarks***

* (1) It uses a timeout of *-1* (no timeout)
* This operation might receive less data than *len*. Use the free function *asyncReceive* to receive a buffer in is entirety.

### <a name="socket-cancel">Socket::cancel</a>

```cpp
void cancel();
```

Cancels all outstanding asynchronous operations. The handlers for the cancelled operations will be passed the *Error::Code::Cancelled* error.

### <a name="socket-getservice">Socket::getService</a>

```cpp
Service& getService();
```

***Return value***

The Service associated with this object.

### <a name="socket-setlinger">Socket::setLinger</a>

```cpp
void setLinger(bool enabled, unsigned short timeoutSeconds);
```

Controls the SO_LINGER socket options.

***Remarks***

You should know what SO_LINGER does before trying to use this function.

### <a name="socket-getlocaladdr">Socket::getLocalAddr</a>

```cpp
const std::pair<std::string, int>& getLocalAddr() const;
```

***Return value***

Returns the local address of the socket (ip and port).

### <a name="socket-getpeeraddr">Socket::getPeerAddr</a>

```cpp
const std::pair<std::string, int>& getPeerAddr() const;
```

***Return value***

Returns the peer address of the socket (ip and port).

### <a name="socket-gethandle">Socket::getHandle</a>

```cpp
SocketHandle getHandle();
```

***Return value***

The native socket handle.

***Remarks***

This function is provided just as convenience if you wish to do something czspas doesn't support. BE CAREFUL with what you do with the handle.

## Free functions

Free functions are all the functions that are not methods of a class

### send

```cpp
size_t send(Socket& sock, const char* buf, size_t len, Error& ec); // (1)
size_t send(Socket& sock, const char* buf, size_t len, int timeoutMs, Error& ec); // (2)
```

Synchronously sends a buffer. It will block until all the data is sent, or an error occurs.

***Parameters***

* **sock** : Socket used to send the data
* **buf** : Data to send
* **len** : Size of the data to send
* **timeoutMs** : The timeout for the operation in milliseconds.
* **ec** : Where you'll get the operation result (success or an error)

***Return value***

Number of bytes sent.

If an error occurred (check *ec*) this may be smaller than *len*.

Note that this doesn't necessarily means the peer received the data. Just means the data was passed to the Operating System's transport layer.

***Remarks***

Note that contrary to the *Socket::sendSome*, this function will try to send all the data instead of returning as soon as some data is sent.

This function is implemented as multiple calls to *Socket::sendSome*, so don't call any other send operation on the same Socket while this one is running.

(1) Assumes a timeout of -1 (no timeout)

### asyncSend

```cpp
void asyncSend(Socket& sock, const char* buf, size_t len, TransferHandler&& h); // (1)
void asyncSend(Socket& sock, const char* buf, size_t len, int TimeoutMs, TransferHandler&& h); // (2)
```

Asynchronously sends data. The provided handler is called when all the data was sent or an error occurs.

***Parameters***

* **sock** : Socket used to send the data
* **buf** : Data to send
* **len** : Size of the data to send
* **timeoutMs** : The timeout for the operation in milliseconds.
* **h** : Completion handler for the operation.

***Remarks***

Note that contrary to *Socket::asyncSendSome*, this function will try to send all the data instead of considering the operation complete as soon as some data was sent.

This function is implemented as multiple calls to *Socket::asyncSendSome*, so don't call any send operations on the same Socket while this one is running.

(1) Assumes a timeout of -1 (no timeout)

## receive

```cpp
size_t receive(Socket& sock, char* buf, size_t len, Error& ec); // (1)
size_t receive(Socket& sock, char* buf, size_t len, int timeoutMs,  Error& ec); // (2)
```

Synchronously receives data. It will block until the amount of data specified is received or an error occurs.

***Parameters***

* **sock** : Socket used to receive the data
* **buf** : Where to receive the data
* **len** : Size of the data to receive
* **timeoutMs** : The timeout for the operation in milliseconds.
* **ec** : Where you'll get the operation result (success or an error)

***Return value***

Number of bytes received.

If an error occurred (check *ec*) this may be smaller than *len*.

***Remarks***

Note that contrary to the *Socket::receiveSome*, this function will try to receive the amount of data specified instead of returning as soon as some data is received.

This function is implemented as multiple calls to *Socket::receiveSome*, so don't call any other receive operations on the same Socket while this one is running.

(1) Assumes a timeout of -1 (no timeout)

## asyncReceive

```cpp
void asyncReceive(Socket& sock, char* buf, size_t len, TransferHandler&& h); // (1)
void asyncReceive(Socket& sock, char* buf, size_t len, int timeoutMs, TransferHandler&& h); // (2)
```

Asynchronously receives data. The provided handler is called when the amount of data specified is received or an error occurred.

***Parameters***

* **sock** : Socket used to send the data
* **buf** : Where to receive the data
* **len** : Size of the data to receive
* **timeoutMs** : The timeout for the operation in milliseconds.
* **h** : Completion handler for the operation.

***Remarks***

Note that contrary to *Socket::asyncReceiveSome*, this function will try to receive the amount of data specified instead of considering the operation complete as soon as some data is received.

This function is implemented as multiple calls to *Socket::asyncReceiveSome*, so don't call any send operations on the same Socket while this one is running.

(1) Assumes a timeout of -1 (no timeout)
