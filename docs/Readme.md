<a id="top"></a>

**Examples**

* [Unit Tests](Examples.md#unittests)
* [EchoServer](Examples.md#echoserver)
* [EchoSynchronousClient](Examples.md#echosynchronousclient)
* [EchoAsynchronousClient](Examples.md#echoasynchronousclient)

**API**
* [Overall design](API.md#overall-design)
* [Guarantees and expectations](API.md#guarantees-and-expectations)
* [Type of callbacks](API.md#type-of-callbacks)
* [Error](API.md#error)
	* [Constructor](API.md#error-constructor)
	* [msg](API.md#error-msg)
	* [setMsg](API.md#error-setmsg)
	* [operator bool()](API.md#error-operator-bool)
	* [code](API.md#error-code)
* [Service](API.md#service)
	* [run](API.md#service-run)
	* [post](API.md#service-post)
	* [stop](API.md#service-stop)
	* [isStopped](API.md#service-isstopped)
	* [reset](API.md#service-reset)
* [Acceptor](API.md#acceptor)
	* [Constructor](API.md#acceptor-constructor)
	* [listen](API.md#acceptor-listen)
	* [accept](API.md#acceptor-accept)
	* [asyncAccept](API.md#acceptor-asyncaccept)
	* [cancel](API.md#acceptor-cancel)
	* [getService](API.md#acceptor-getservice)
	* [setLinger](API.md#acceptor-setlinger)
	* [getLocalAddr](API.md#acceptor-getlocaladdr)
	* [getHandle](API.md#acceptor-gethandle)
* [Socket](API.md#socket)
	* [Constructor](API.md#socket-constructor)
	* [connect](API.md#socket-connect)
	* [asyncConnect](API.md#socket-asyncconnect)
	* [sendSome](API.md#socket-sendsome)
	* [asyncSendSome](API.md#socket-asyncsendsome)
	* [receiveSome](API.md#socket-receivesome)
	* [asyncReceiveSome](API.md#socket-asyncreceivesome)
	* [cancel](API.md#socket-cancel)
	* [getService](API.md#socket-getservice)
	* [setLinger](API.md#socket-setlinger)
	* [getLocalAddr](API.md#socket-getlocaladdr)
	* [getPeerAddr](API.md#socket-getpeeraddr)
	* [getHandle](API.md#socket-gethandle)
* [Free functions](API.md#free-functions)
	* [send](API.md#send)
	* [asyncSend](API.md#asyncsend)
	* [receive](API.md#receive)
	* [asyncReceive](API.md#asyncreceive)


DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>

<a id="top2"></a>
**TOP2**

DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>
DUMMY<br>


