#include "testsPCH.h"
using namespace cz;
using namespace spas;

extern UnitTest::Timer gTimer;
#define INTENSIVE_TEST 0
// Default port to use for the tests
#define SERVER_PORT 9000

// A port we know its not available, so we can test listen failure
// On windows we use epmap (port 135)
#define SERVER_UNUSABLE_PORT 135

using namespace cz::spas;

#define CHECK_CZSPAS_EQUAL(expected, ec)                                                                      \
	if ((ec.code) != (Error::Code::expected))                                                                 \
	{                                                                                                         \
		UnitTest::CheckEqual(*UnitTest::CurrentTest::Results(), Error(Error::Code::expected).msg(), ec.msg(), \
		                     UnitTest::TestDetails(*UnitTest::CurrentTest::Details(), __LINE__));             \
	}
#define CHECK_CZSPAS(ec) CHECK_CZSPAS_EQUAL(Success, ec)

#include "tests_spas_helper.h"

SUITE(CZSPAS)
{
//////////////////////////////////////////////////////////////////////////
// Service/Reactor tests
//////////////////////////////////////////////////////////////////////////

// Try to exhaust OS resources by creating tons of Service objects.
// Internally, czspas uses 2 sockets to allow interrupting a wsapoll/poll call.
// This makes sure those sockets are not going into the TIME_WAIT state.
TEST(Service_Reactor_internal_sockets)
{
	std::atomic<int> done(0);

	std::vector<std::future<void>> fts;
	const int numThreads = INTENSIVE_TEST ? 8 : 4;
	const int itemsPerThread = INTENSIVE_TEST ? 9000 : 1000;

	for (int i = 0; i < numThreads; i++)
	{
		fts.push_back(std::async(std::launch::async, [&done, itemsPerThread]
		{
			int todo = itemsPerThread;
			while (todo--)
			{
				Service service;
				++done;
			}

		}));
	}

	for (auto&& ft : fts)
		ft.wait();

	CHECK_EQUAL(numThreads*itemsPerThread, done.load());
}

//////////////////////////////////////////////////////////////////////////
// Acceptor tests
//////////////////////////////////////////////////////////////////////////
// Checks behavior for a simple listen
TEST(Acceptor_listen_ok)
{
	Service io;
	Acceptor ac(io);
	auto ec = ac.listen(SERVER_PORT);
	CHECK_CZSPAS(ec);
}

// Checks behavior when trying to listen on an invalid port
TEST(Acceptor_listen_failure)
{
	Service io;
	Acceptor ac(io);
	auto ec = ac.listen(SERVER_UNUSABLE_PORT);
	CHECK_CZSPAS_EQUAL(Other, ec);
}

TEST(Acceptor_asyncAccept_ok)
{
	ServiceThread ioth;

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);

	Semaphore done;
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	ac->acceptor.asyncAccept(serverSideSession->sock, -1, [&done, this_=ac, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
		done.notify();
	});
	serverSideSession = nullptr;

	Socket clientSock(ioth.service);
	auto ec = clientSock.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS(ec);

	done.wait();
}

// Tests the accept timeout behavior
// Because internally the timeout is split in two fields (microseconds and seconds, because it uses select), we need to
// test something below 1 second, and something above, to make sure the split is done correctly
TEST(Acceptor_accept_timeout)
{
	Service io;
	Acceptor ac(io);
	auto ec = ac.listen(SERVER_PORT);
	CHECK_CZSPAS(ec);

	Socket s(io);
	UnitTest::Timer timer;
	timer.Start();
	ec = ac.accept(s, 50);
	CHECK_CLOSE(50, timer.GetTimeInMs(), 200);
	CHECK_CZSPAS_EQUAL(Timeout, ec);

	timer.Start();
	ec = ac.accept(s, 1050);
	CHECK_CLOSE(1050, timer.GetTimeInMs(), 200);
	CHECK_CZSPAS_EQUAL(Timeout, ec);
}

TEST(Acceptor_asyncAccept_cancel)
{
	ServiceThread ioth;

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);

	Semaphore done;
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	ac->acceptor.asyncAccept(serverSideSession->sock, -1, [&done, this_=ac, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS_EQUAL(Cancelled, ec);
		done.notify();
	});

	ioth.service.post([ac]
	{
		ac->acceptor.cancel();
	});

	done.wait();
}

TEST(Acceptor_asyncAccept_timeout)
{
	ServiceThread ioth;

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);

	Semaphore done;
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	auto start = ioth.timer.GetTimeInMs();
	ac->acceptor.asyncAccept(serverSideSession->sock, 50,
		[&done, start, &ioth, this_=ac, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS_EQUAL(Timeout, ec);
		auto elapsed = ioth.timer.GetTimeInMs() - start;
		CHECK_CLOSE(50.0, elapsed, 1000); // Giving a big tolerance, since the API doesn't guarantee any specific tolerance.
		done.notify();
	});

	done.wait();
}

//////////////////////////////////////////////////////////////////////////
// Socket tests
//////////////////////////////////////////////////////////////////////////

TEST(Socket_connect_ok)
{
	ServiceThread ioth;

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);

	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	ac->acceptor.asyncAccept(serverSideSession->sock, -1, [this_=ac, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
	});

	Socket clientSock(ioth.service);
	auto ec = clientSock.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS(ec);
}

TEST(Socket_connect_failure)
{
	ServiceThread ioth;
	Socket clientSock(ioth.service);
	auto ec = clientSock.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS_EQUAL(Other,ec);
}

TEST(Socket_asyncConnect_ok)
{
	ServiceThread ioth;

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	Semaphore done;
	ac->acceptor.asyncAccept(serverSideSession->sock, -1, [this_=ac, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
	});

	auto clientSideSession = std::make_shared<Session<>> (ioth.service);
	clientSideSession->sock.asyncConnect("127.0.0.1", SERVER_PORT, -1, [&done, con = clientSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
		done.notify();
	});

	done.wait();
}

// Initially I was using "127.0.0.1" to test the asynchronous connect timeout or cancel, but it seems that on linux
// it fails right away. Probably the kernel treats connections to the localhost in a different way, detecting
// right away that if a connect is not possible, without taking into consideration the timeout specified in
// the "select" function.
// On Windows, connect attempts to localhost still take into consideration the timeout.
// The solution is to try an connect to some external ip, like "254.254.254.254". This causes Linux to
// to actually wait for the connect attempt.
TEST(Socket_asyncConnect_cancel)
{
	ServiceThread ioth;

	Semaphore done;
	auto clientSideSession = std::make_shared<Session<>> (ioth.service);
	clientSideSession->sock.asyncConnect("254.254.254.254", SERVER_PORT, -1, [&done, con = clientSideSession](const Error& ec)
	{
		CHECK_CZSPAS_EQUAL(Cancelled, ec);
		done.notify();
	});

	ioth.service.post([&done, con = clientSideSession]
	{
		con->sock.cancel();
		done.notify();
	});

	done.wait();
	done.wait();
}

TEST(Socket_asyncConnect_timeout)
{
	ServiceThread ioth;

	Semaphore done;
	auto clientSideSession = std::make_shared<Session<>> (ioth.service);
	auto start = gTimer.GetTimeInMs();
	clientSideSession->sock.asyncConnect("254.254.254.254", SERVER_PORT, 50, [&done, start, con = clientSideSession](const Error& ec)
	{
		auto elapsed = gTimer.GetTimeInMs() - start;
		CHECK_CLOSE(50.0, elapsed, 1000); // Giving a big tolerance, since the API doesn't guarantee any specific tolerance.
		CHECK_CZSPAS_EQUAL(Timeout, ec);
		done.notify();
	});

	done.wait();
}

TEST(Socket_asyncSendSome_asyncReceiveSome_ok)
{
	ServiceThread ioth;

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	Semaphore done;
	ac->acceptor.asyncAccept(serverSideSession->sock, -1, [&done, this_=ac, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
		static uint32_t buf;
		con->sock.asyncReceiveSome(reinterpret_cast<char*>(&buf), sizeof(buf), -1,
			[&done, con, bufPtr=&buf](const Error& ec, size_t transfered)
		{
			// Note: Capturing bufPtr is not necessary, but makes it easier to debug.
			CHECK_EQUAL(4, transfered);
			CHECK_EQUAL(0x11223344, *bufPtr);
			done.notify();
		});
	});

	auto clientSideSession = std::make_shared<Session<>> (ioth.service);
	clientSideSession->sock.asyncConnect("127.0.0.1", SERVER_PORT, -1, [con = clientSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
		static uint32_t buf = 0x11223344;
		con->sock.asyncSendSome(reinterpret_cast<char*>(&buf), sizeof(buf), -1,
			[con](const Error& ec, size_t transfered)
		{
			CHECK_EQUAL(4, transfered);
		});
	});

	done.wait();
}

TEST(Socket_asyncReceiveSome_cancel)
{
	ServiceThread ioth;

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	Semaphore done;
	ac->acceptor.asyncAccept(serverSideSession->sock, -1, [&done, this_=ac, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
	});

	auto clientSideSession = std::make_shared<Session<>> (ioth.service);
	auto ec = clientSideSession->sock.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS(ec);
	char rcvBuf[4];
	clientSideSession->sock.asyncReceiveSome(rcvBuf, sizeof(rcvBuf), -1,
		[&done, con = clientSideSession](const Error& ec, size_t transfered)
	{
		CHECK_CZSPAS_EQUAL(Cancelled, ec);
		CHECK_EQUAL(0, transfered);
		done.notify();
	});

	ioth.service.post([con = clientSideSession]
	{
		con->sock.cancel();
	});

	done.wait();
}

TEST(Socket_asyncReceiveSome_timeout)
{
	ServiceThread ioth;

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	Semaphore done;
	ac->acceptor.asyncAccept(serverSideSession->sock, -1, [&done, this_=ac, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
	});

	auto clientSideSession = std::make_shared<Session<>> (ioth.service);
	auto ec = clientSideSession->sock.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS(ec);
	char rcvBuf[4];
	auto start = gTimer.GetTimeInMs();
	clientSideSession->sock.asyncReceiveSome(rcvBuf, sizeof(rcvBuf), 50,
		[&done, start, con = clientSideSession](const Error& ec, size_t transfered)
	{
		auto elapsed = gTimer.GetTimeInMs() - start;
		CHECK_CLOSE(50.0, elapsed, 1000); // Giving a big tolerance, since the API doesn't guarantee any specific tolerance.
		CHECK_CZSPAS_EQUAL(Timeout, ec);
		CHECK_EQUAL(0, transfered);
		done.notify();
	});

	done.wait();
}

TEST(Socket_asyncReceiveSome_peerDisconnect)
{
	ServiceThread ioth;

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	Semaphore done;
	ac->acceptor.asyncAccept(serverSideSession->sock, -1, [&done, this_=ac, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
	});
	serverSideSession = nullptr;

	auto clientSideSession = std::make_shared<Session<>> (ioth.service);
	auto ec = clientSideSession->sock.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS(ec);
	char rcvBuf[4];
	clientSideSession->sock.asyncReceiveSome(rcvBuf, sizeof(rcvBuf), -1,
		[&done, con = clientSideSession](const Error& ec, size_t transfered)
	{
		CHECK_CZSPAS_EQUAL(ConnectionClosed, ec);
		CHECK_EQUAL(0, transfered);
		done.notify();
	});

	done.wait();
}

//
// Successfully cancelling an asynchronous send operation is hard in practice, since most of the time a socket is marked
// as ready to send by the OS.
// The only feasible way to correctly test the cancel in this case is to do a cancel right after the send from the 
// Service thread itself, so the Reactor doesn't have a chance to run.
TEST(Socket_asyncSendSome_cancel)
{
	ServiceThread ioth;

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	Semaphore done;
	ac->acceptor.asyncAccept(serverSideSession->sock, -1, [&done, this_=ac, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
		static char sndBuf[4];
		// Do the two calls here inside the Service thread, so the Reactor doesn't have the chance to initiate the
		// send
		con->sock.asyncSendSome(sndBuf, sizeof(sndBuf), -1, [&done, con](const Error& ec, size_t transfered)
		{
			CHECK_CZSPAS_EQUAL(Cancelled, ec);
			CHECK_EQUAL(0, transfered);
			done.notify();
		});

		con->sock.cancel();
	});

	auto clientSideSession = std::make_shared<Session<>> (ioth.service);
	auto ec = clientSideSession->sock.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS(ec);

	done.wait();
}

TEST(Socket_asyncSendSome_timeout)
{
	// #TODO: I can't think of a feasible way to test a send timeout, since most of the time a socket will be ready
	// to write.
	// Internally, the Reactor tries to do the send/recv before checking the timeout, so if the socket is always ready
	// to write, the send timeout is very hard to test.
}

TEST(Socket_asyncSendSome_peerDisconnect)
{
	ServiceThread ioth;

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	Semaphore done;
	ac->acceptor.asyncAccept(serverSideSession->sock, -1, [&done, this_=ac, con = serverSideSession](const Error& ec) mutable
	{
		CHECK_CZSPAS(ec);
		con = nullptr; // So the socket is destroyed right now
		done.notify();
	});
	serverSideSession = nullptr;

	auto clientSideSession = std::make_shared<Session<>> (ioth.service);
	auto ec = clientSideSession->sock.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS(ec);
	done.wait(); // wait for the peer to disconnect, so when we try to send, the peer disconnected already
	char sndBuf[4];
	clientSideSession->sock.asyncSendSome(sndBuf, sizeof(sndBuf), -1,
		[&done, &sndBuf, con = clientSideSession](const Error& ec, size_t transfered)
	{
		// It might happen we detect the connection as closed right away, or the OS still considers some data was sent
		if (ec.code == Error::Code::ConnectionClosed)
		{
			CHECK_EQUAL(0, transfered);
			done.notify();
		}
		else
		{
			CHECK_CZSPAS(ec);
			CHECK(transfered > 0);
			// Try another send. This one should already fail
			con->sock.asyncSendSome(sndBuf, sizeof(sndBuf), -1,
				[&done, con](const Error& ec, size_t transfered)
			{
				CHECK_CZSPAS_EQUAL(ConnectionClosed, ec);
				CHECK_EQUAL(0, transfered);
				done.notify();
			});
		}
	});

	done.wait();
}


// Create and destroy lots of connections really fast, to make sure we can set lingering off
void Socket_multiple_connections_acceptorHelper(std::shared_ptr<AcceptorSession<>> session, std::atomic<int>& numAccepts)
{
	auto serverSideSession = std::make_shared<Session<>>(session->acceptor.getService());
	session->acceptor.asyncAccept(serverSideSession->sock, -1, [&numAccepts, this_ = session, con = serverSideSession](const Error& ec) mutable
	{
		CHECK_CZSPAS(ec);
		++numAccepts;
		Socket_multiple_connections_acceptorHelper(this_, numAccepts);
	});
}

TEST(Socket_multiple_connections)
{
	std::vector<std::future<void>> fts;

	const int numThreads = INTENSIVE_TEST ? 8 : 4;
	const int itemsPerThread = INTENSIVE_TEST ? 9000 : 1000;

	std::atomic<int> numAccepts(0);
	std::atomic<int> numDone(0);

	for (int i = 0; i < numThreads; i++)
	{
		auto ft = std::async(std::launch::async, [&numAccepts, &numDone, &itemsPerThread, i]
		{
			ServiceThread ioth;

			auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT+i);
			Semaphore done;
			Socket_multiple_connections_acceptorHelper(ac, numAccepts);

			int todo = itemsPerThread;
			while (todo--)
			{
				Socket client(ioth.service);
				auto ec = client.connect("127.0.0.1", SERVER_PORT+i);
				CHECK_CZSPAS(ec);
				client.setLinger(true, 0);
				client._forceClose(false);
				++numDone;
			}
		});
		fts.push_back(std::move(ft));
	}

	for (auto&& ft : fts)
		ft.wait();

	CHECK_EQUAL(numThreads*itemsPerThread, numDone.load());
}

TEST(Socket_bigTransfer)
{

	constexpr size_t bigbufsize = INTENSIVE_TEST ? (size_t(INT_MAX) + 1) : (size_t(INT_MAX) / 4);

	auto serverth = std::thread( [bigbufsize]{
		ServiceThread ioth;
		auto bigbuf = std::shared_ptr<char>(new char[bigbufsize], [](char* p) { delete[] p; });

		Acceptor acceptor(ioth.service);
		acceptor.listen(SERVER_PORT);
		auto sock = std::make_shared<Socket>(ioth.service);
		auto ec = acceptor.accept(*sock);
		CHECK_CZSPAS(ec);
		Semaphore done;
		asyncReceive(*sock, bigbuf.get(), bigbufsize, -1, [&, sock, bigbuf](const Error& ec, size_t transfered)
		{
			CHECK_CZSPAS(ec);
			CHECK_EQUAL(bigbufsize, transfered);
			auto ptr = bigbuf.get();
			for (size_t i = 0; i < bigbufsize; i++)
			{
				CHECK_EQUAL(int(char(i)), int(ptr[i]));
			}
			done.notify();
		});

		done.wait();
	});

	auto clientth = std::thread( [bigbufsize]{
		ServiceThread ioth;
		auto bigbuf = std::shared_ptr<char>(new char[bigbufsize], [](char* p) { delete[] p; });
		auto ptr = bigbuf.get();
		for (size_t i = 0; i < bigbufsize; i++)
			ptr[i] = (char)i;

		auto sock = std::make_shared<Socket>(ioth.service);
		auto ec = sock->connect("127.0.0.1", SERVER_PORT);
		CHECK_CZSPAS(ec);
		Semaphore done;
		asyncSend(*sock, bigbuf.get(), bigbufsize, -1, [&, sock, bigbuf](const Error& ec, size_t transfered)
		{
			CHECK_CZSPAS(ec);
			CHECK_EQUAL(bigbufsize, transfered);
			done.notify();
		});
		done.wait();
	});

	serverth.join();
	clientth.join();
}

TEST(Socket_synchronous_Send_Receive_ok)
{
	Service service;

	Acceptor ac(service);
	auto ec = ac.listen(SERVER_PORT);
	CHECK_CZSPAS(ec);

	Socket sender(service);
	ec = sender.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS(ec);

	Socket receiver(service);
	ec = ac.accept(receiver);
	CHECK_CZSPAS(ec);

	const char* outBuf = "Hello World!";
	auto done = sender.sendSome("Hello World!", strlen(outBuf), -1, ec);
	CHECK_EQUAL(strlen(outBuf), done);
	CHECK_CZSPAS(ec);

	char inBuf[64];
	memset(inBuf, 0, sizeof(inBuf));
	done = receiver.receiveSome(inBuf, sizeof(inBuf), -1, ec);
	CHECK_EQUAL(strlen(outBuf), done);
	CHECK_CZSPAS(ec);
	CHECK_EQUAL(outBuf, inBuf);
}

TEST(Socket_synchronous_receive_timeout)
{
	ServiceThread ioth;
	Service service;

	Acceptor ac(service);
	auto ec = ac.listen(SERVER_PORT);
	CHECK_CZSPAS(ec);

	Socket sender(service);
	ec = sender.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS(ec);

	Socket receiver(service);
	ec = ac.accept(receiver);
	CHECK_CZSPAS(ec);

	// Test receive timeout, since there is no more data to read
	char inBuf[1];
	auto start = gTimer.GetTimeInMs();
	auto done = receiver.receiveSome(inBuf, sizeof(inBuf), 20, ec);
	CHECK_CLOSE(20, gTimer.GetTimeInMs() - start, 200);
	CHECK_EQUAL(0, done);
	CHECK_CZSPAS_EQUAL(Timeout, ec);
}

TEST(Socket_synchronous_receive_disconnect)
{
	ServiceThread ioth;
	Service service;

	Acceptor ac(service);
	auto ec = ac.listen(SERVER_PORT);
	CHECK_CZSPAS(ec);

	Socket sender(service);
	ec = sender.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS(ec);

	Socket receiver(service);
	ec = ac.accept(receiver);
	CHECK_CZSPAS(ec);

	sender._forceClose(false);
	char inBuf[1];
	auto done = receiver.receiveSome(inBuf, sizeof(inBuf), -1, ec);
	CHECK_EQUAL(0, done);
	CHECK_CZSPAS_EQUAL(ConnectionClosed, ec);
}

TEST(Socket_synchronous_receive_error)
{
	ServiceThread ioth;
	Service service;

	Acceptor ac(service);
	auto ec = ac.listen(SERVER_PORT);
	CHECK_CZSPAS(ec);

	Socket sender(service);
	ec = sender.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS(ec);

	Socket receiver(service);
	ec = ac.accept(receiver);
	CHECK_CZSPAS(ec);

	// Close our own socket before sending, just to test error detection
	auto h = receiver.getHandle(); // Copying to a local, since detail::utils::closeSocket clears the input
	detail::utils::closeSocket(h);
	char inBuf[1];
	auto done = receiver.receiveSome(inBuf, sizeof(inBuf), -1, ec);
	CHECK_EQUAL(0, done);
	CHECK_CZSPAS_EQUAL(Other, ec);
}

TEST(Socket_synchronous_send_timeout)
{
	// #TODO : No idea how to test this one :(
}

TEST(Socket_synchronous_send_disconnect)
{
	ServiceThread ioth;
	Service service;

	Acceptor ac(service);
	auto ec = ac.listen(SERVER_PORT);
	CHECK_CZSPAS(ec);

	Socket sender(service);
	ec = sender.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS(ec);

	Socket receiver(service);
	ec = ac.accept(receiver);
	CHECK_CZSPAS(ec);
	receiver._forceClose(false);

	// Even thought the peer was closed, a send can still say it succeeded, so we need to loop until it eventually
	// fails to test the desired code path.
	size_t done;
	while (!ec)
	{
		char outBuf[2];
		done = sender.sendSome(outBuf, sizeof(outBuf), -1, ec);
		if (!ec)
			CHECK_EQUAL(2, done);
	}
	CHECK_EQUAL(0, done);
	CHECK_CZSPAS_EQUAL(Other, ec);
}

TEST(Socket_synchronous_send_error)
{
	ServiceThread ioth;
	Service service;

	Acceptor ac(service);
	auto ec = ac.listen(SERVER_PORT);
	CHECK_CZSPAS(ec);

	Socket sender(service);
	ec = sender.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS(ec);

	Socket receiver(service);
	ec = ac.accept(receiver);
	CHECK_CZSPAS(ec);

	// Close our own socket before sending, just to test error detection
	auto h = sender.getHandle(); // Copying to a local, since detail::utils::closeSocket clears the input
	detail::utils::closeSocket(h);
	char outBuf[1];
	auto done = sender.sendSome(outBuf, sizeof(outBuf), -1, ec);
	CHECK_EQUAL(0, done);
	CHECK_CZSPAS_EQUAL(Other, ec);
}


}
