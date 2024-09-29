# Examples

Not many samples provided, but since the API design is somewhat similar to Asio, I guess you can manage. :)

## <a name="unittests">Unit tests</a>

The unit tests are not documentation per se, but might provide some tips when in doubt. Just take into account that they are a bit verbose by nature.

## <a name="echoserver">EchoServer</a>

This demonstrates a simple server that waits for connections. Once a client connects and sends back a string, the server replies with the same string
It's a good example on how to manage lifetime issues.
It's similar to the equivalent Asio sample you can find at [http://think-async.com/Asio/asio-1.10.6/src/examples/cpp11/echo/async_tcp_echo_server.cpp](http://think-async.com/Asio/asio-1.10.6/src/examples/cpp11/echo/async_tcp_echo_server.cpp)

## <a name="echosynchronousclient">EchoSynchronousClient</a>

Connects to a EchoServer, sends a string and waits for the reply.
This shows how to use the synchronous API. For servers, the asynchronous API is preferable since it makes it easier to manage multiple connections. But for a client that doesn't need to do much, the synchronous API can make for shorter code.

## <a name="echoasynchronousclient">EchoAsynchronousClient</a>

Connects to a EchoServer, sends a string and waits for the reply.
This shows how to use the asynchronous API. For a client this simple the synchronous API is simpler, but this example is still available for reference.
