
using namespace cz;
using namespace spas;

#define INTENSIVE_TEST 0
// Default port to use for the tests
#define SERVER_PORT 9000

// A port we know its not available, so we can test listen failure
// On windows we use epmap (port 135)
#define SERVER_UNUSABLE_PORT 135

// This is the ip of example.com
// Using this to test some of the timeouts
#define TIMEOUT_TEST_IP "93.184.216.34"

using namespace cz::spas;

#define CHECK_CZSPAS_EQUAL(expected, ec)    \
	CHECK(ec.code == Error::Code::expected)

#define CHECK_CZSPAS(ec) CHECK_CZSPAS_EQUAL(Success, ec)

#include "tests_spas_helper.h"


//////////////////////////////////////////////////////////////////////////
// Service/Reactor tests
//////////////////////////////////////////////////////////////////////////

// Try to exhaust OS resources by creating tons of Service objects.
// Internally, czspas uses 2 sockets to allow interrupting a wsapoll/poll call.
// This makes sure those sockets are not going into the TIME_WAIT state.
TEST_CASE("Service_Reactor_internal_sockets")
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

	CHECK(numThreads*itemsPerThread == done.load());
}

// Tests a call to Service::run when there is no work
TEST_CASE("Service_run_nowork")
{
	Service service;
	auto done = service.run();
	CHECK(done == 0);
	CHECK(service.isStopped());
}

// Tests a call to Service::run when it has a dummy work to keep the run() call alive
// After an interval, it destroys the work item, which should cause the call to run() to unblock
TEST_CASE("Service_run_work_release")
{
	Service service;
	auto work = std::make_unique<Service::Work>(service); // Dummy work item

	auto ft = std::async(std::launch::async, [&work]
	{
		std::this_thread::sleep_for(100ms);
		work.reset();
	});

	auto done = service.run();
	CHECK(done == 0);
	CHECK(service.isStopped());
}

// Tests a call to Service::run when it has a dummy work to keep the run() call alive
// After an interval, it calls Service::stop . This should cause the call to run() to unblock even though the work item
// still exists
TEST_CASE("Service_run_work_stop")
{
	Service service;
	auto work = std::make_unique<Service::Work>(service); // Dummy work item

	auto ft = std::async(std::launch::async, [&service]
	{
		std::this_thread::sleep_for(100ms);
		service.stop();
	});

	auto done = service.run();
	CHECK(done == 0);
	CHECK(service.isStopped());
}

//////////////////////////////////////////////////////////////////////////
// Acceptor tests
//////////////////////////////////////////////////////////////////////////
// Checks behaviour for a simple listen
TEST_CASE("Acceptor_listen_ok")
{
	Service io;
	Acceptor ac(io);
	auto ec = ac.listen(SERVER_PORT);
	CHECK_CZSPAS(ec);
}

TEST_CASE("Acceptor_getLocalAddr")
{
	Service io;
	// Listening on all interfaces
	{
		Acceptor ac(io);
		auto ec = ac.listen(SERVER_PORT);
		CHECK_CZSPAS(ec);
		auto addr = ac.getLocalAddr();
		CHECK(addr.first == "0.0.0.0");
		CHECK(addr.second == SERVER_PORT);
	}
	// Listening on a specific interface
	{
		Acceptor ac(io);
		bool reuseAddr = false;
#if __linux__
		reuseAddr = true;
#endif
		auto ec = ac.listen("127.0.0.1", SERVER_PORT, SOMAXCONN, reuseAddr);
		CHECK_CZSPAS(ec);
		auto addr = ac.getLocalAddr();
		CHECK(addr.first == "127.0.0.1");
		CHECK(addr.second == SERVER_PORT);
	}
}

// Checks behaviour when trying to listen on an invalid port
TEST_CASE("Acceptor_listen_failure")
{
	Service io;
	Acceptor ac(io);
	auto ec = ac.listen(SERVER_UNUSABLE_PORT);
	CHECK_CZSPAS_EQUAL(Other, ec);
}

TEST_CASE("Acceptor_asyncAccept_ok")
{
	ServiceThread ioth(true, true, true);

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);

	Semaphore done;
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	ac->acceptor.asyncAccept(serverSideSession->sock, [&done, this_=ac, con = serverSideSession](const Error& ec)
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

std::chrono::steady_clock::time_point getTime()
{
	return std::chrono::steady_clock::now();
}

#define CHECK_DELTA_TIME(from, to, expected, tolerance) \
	CHECK( abs((to - from) - expected) <= tolerance )


// Tests the accept timeout behaviour
// Because internally the timeout is split in two fields (microseconds and seconds, because it uses select), we need to
// test something below 1 second, and something above, to make sure the split is done correctly
TEST_CASE("Acceptor_accept_timeout")
{
	Service io;
	Acceptor ac(io);
	auto ec = ac.listen(SERVER_PORT);
	CHECK_CZSPAS(ec);

	Socket s(io);
	auto start = getTime();
	ec = ac.accept(s, 50);

	CHECK_DELTA_TIME(start, getTime(), 50ms, 20ms);
	CHECK_CZSPAS_EQUAL(Timeout, ec);

	start = getTime();
	ec = ac.accept(s, 1050);
	CHECK_DELTA_TIME(start, getTime(), 1050ms, 20ms);
	CHECK_CZSPAS_EQUAL(Timeout, ec);
}

TEST_CASE("Acceptor_asyncAccept_cancel")
{
	ServiceThread ioth(false, false, false);

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);

	Semaphore done;
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	ac->acceptor.asyncAccept(serverSideSession->sock, [&done, this_=ac, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS_EQUAL(Cancelled, ec);
		done.notify();
	});

	ioth.run();

	ioth.service.post([ac]
	{
		ac->acceptor.cancel();
	});

	done.wait();
}

TEST_CASE("Acceptor_asyncAccept_timeout")
{
	ServiceThread ioth(true, true, true);

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);

	Semaphore done;
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	auto start = getTime();
	ac->acceptor.asyncAccept(serverSideSession->sock, 50,
		[&done, start, &ioth, this_=ac, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS_EQUAL(Timeout, ec);
		CHECK_DELTA_TIME(start, getTime(), 50ms, 1000ms); // Giving a big tolerance, since the API doesn't guarantee any specific tolerance.
		done.notify();
	});

	done.wait();
}

//////////////////////////////////////////////////////////////////////////
// Socket tests
//////////////////////////////////////////////////////////////////////////

TEST_CASE("Socket_connect_ok")
{
	ServiceThread ioth(false, false, false);

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);

	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	ac->acceptor.asyncAccept(serverSideSession->sock, [this_=ac, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
	});

	ioth.run();

	Socket clientSock(ioth.service);
	auto ec = clientSock.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS(ec);
}

TEST_CASE("Socket_getLocalAddr_getPeerAddr")
{
	ServiceThread ioth(true, true, true);

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);

	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	Semaphore done;
	ac->acceptor.asyncAccept(serverSideSession->sock, [this_=ac, &done, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
		done.notify();
	});

	Socket clientSock(ioth.service);
	auto ec = clientSock.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS(ec);
	done.wait();

	// Check server side things
	auto serverLocal = serverSideSession->sock.getLocalAddr();
	auto serverPeer = serverSideSession->sock.getPeerAddr();
	auto clientLocal = clientSock.getLocalAddr();
	auto clientPeer = clientSock.getPeerAddr();

	CHECK("127.0.0.1" == serverLocal.first);
	CHECK("127.0.0.1" == serverPeer.first);
	CHECK("127.0.0.1" == clientLocal.first);
	CHECK("127.0.0.1" == clientPeer.first);

	CHECK(SERVER_PORT == serverLocal.second);
	CHECK(SERVER_PORT == clientPeer.second);
	CHECK( (serverPeer.second != SERVER_PORT && serverPeer.second > 0) );
	CHECK(serverPeer.second == clientLocal.second);
}

TEST_CASE("Socket_connect_failure")
{
	ServiceThread ioth(false, false, false);
	Socket clientSock(ioth.service);
	auto ec = clientSock.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS_EQUAL(Other,ec);
}

TEST_CASE("Socket_asyncConnect_ok")
{
	ServiceThread ioth(false, false, false);

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	Semaphore done;
	ac->acceptor.asyncAccept(serverSideSession->sock, [this_=ac, &done, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
		done.notify();
	});

	ioth.run();

	auto clientSideSession = std::make_shared<Session<>> (ioth.service);
	clientSideSession->sock.asyncConnect("127.0.0.1", SERVER_PORT, [&done, con = clientSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
		done.notify();
	});

	// Wait for it to finish, to see if we got both handlers executed, followed by an automatic exit of Service::run,
	// since it ran out of work
	ioth.finish();
	CHECK(2 == done.getCount());
}

// Initially I was using "127.0.0.1" to test the asynchronous connect timeout or cancel, but it seems that on Linux
// it fails right away. Probably the kernel treats connections to the localhost in a different way, detecting
// right away that if a connect is not possible, without taking into consideration the timeout specified in
// the "select" function.
// On Windows, connect attempts to localhost still take into consideration the timeout.
// The solution is to try a connect to some external ip, like "254.254.254.254".
// This causes Linux to actually wait for the connect attempt.
// NOTE: WSL (Windows Subsystem for Linux) doesn't support non-blocking connects at this moment, so this test will fail
// although it seems in some systems, such has Windows
TEST_CASE("Socket_asyncConnect_cancel")
{
	ServiceThread ioth(true, true, true);

	Semaphore done;
	auto clientSideSession = std::make_shared<Session<>> (ioth.service);
	clientSideSession->sock.asyncConnect("254.254.254.254", SERVER_PORT, [&done, con = clientSideSession](const Error& ec)
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

TEST_CASE("Socket_asyncConnect_timeout")
{
	ServiceThread ioth(true, true, true);

	Semaphore done;
	auto clientSideSession = std::make_shared<Session<>> (ioth.service);
	auto start = getTime();
	clientSideSession->sock.asyncConnect(TIMEOUT_TEST_IP, SERVER_PORT, 200, [&done, start, con = clientSideSession](const Error& ec)
	{
		CHECK_DELTA_TIME(start, getTime(), 200ms, 1000ms); // Giving a big tolerance, since the API doesn't guarantee any specific tolerance.
		CHECK_CZSPAS_EQUAL(Timeout, ec);
		done.notify();
	});

	done.wait();
}

TEST_CASE("Socket_asyncSendSome_asyncReceiveSome_ok")
{
	ServiceThread ioth(true, true, true);

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	Semaphore done;
	ac->acceptor.asyncAccept(serverSideSession->sock, [&done, this_=ac, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
		static uint32_t buf;
		con->sock.asyncReceiveSome(reinterpret_cast<char*>(&buf), sizeof(buf), 
			[&done, con, bufPtr=&buf](const Error& ec, size_t transfered)
		{
			// Note: Capturing bufPtr is not necessary, but makes it easier to debug.
			CHECK(4 == transfered);
			CHECK(0x11223344 == *bufPtr);
			done.notify();
		});
	});

	auto clientSideSession = std::make_shared<Session<>> (ioth.service);
	clientSideSession->sock.asyncConnect("127.0.0.1", SERVER_PORT, [con = clientSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
		static uint32_t buf = 0x11223344;
		con->sock.asyncSendSome(reinterpret_cast<char*>(&buf), sizeof(buf),
			[con](const Error& ec, size_t transfered)
		{
			CHECK(4 == transfered);
		});
	});

	done.wait();
}

TEST_CASE("Socket_asyncReceiveSome_cancel")
{
	ServiceThread ioth(true, true, true);

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	Semaphore done;
	ac->acceptor.asyncAccept(serverSideSession->sock, [&done, this_=ac, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
	});

	auto clientSideSession = std::make_shared<Session<>> (ioth.service);
	auto ec = clientSideSession->sock.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS(ec);
	char rcvBuf[4];
	clientSideSession->sock.asyncReceiveSome(rcvBuf, sizeof(rcvBuf),
		[&done, con = clientSideSession](const Error& ec, size_t transfered)
	{
		CHECK_CZSPAS_EQUAL(Cancelled, ec);
		CHECK(0 == transfered);
		done.notify();
	});

	ioth.service.post([con = clientSideSession]
	{
		con->sock.cancel();
	});

	done.wait();
}

TEST_CASE("Socket_asyncReceiveSome_timeout")
{
	ServiceThread ioth(true, true, true);

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	Semaphore done;
	ac->acceptor.asyncAccept(serverSideSession->sock, [&done, this_=ac, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
	});

	auto clientSideSession = std::make_shared<Session<>> (ioth.service);
	auto ec = clientSideSession->sock.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS(ec);
	char rcvBuf[4];
	auto start = getTime();
	clientSideSession->sock.asyncReceiveSome(rcvBuf, sizeof(rcvBuf), 50,
		[&done, start, con = clientSideSession](const Error& ec, size_t transfered)
	{
		CHECK_DELTA_TIME(start, getTime(), 50ms, 1000ms); // Giving a big tolerance, since the API doesn't guarantee any specific tolerance.
		CHECK_CZSPAS_EQUAL(Timeout, ec);
		CHECK(0 == transfered);
		done.notify();
	});

	done.wait();
}

TEST_CASE("Socket_asyncReceiveSome_peerDisconnect")
{
	ServiceThread ioth(true, true, true);

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	Semaphore done;
	ac->acceptor.asyncAccept(serverSideSession->sock, [&done, this_=ac, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
	});
	serverSideSession = nullptr;

	auto clientSideSession = std::make_shared<Session<>> (ioth.service);
	auto ec = clientSideSession->sock.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS(ec);
	char rcvBuf[4];
	clientSideSession->sock.asyncReceiveSome(rcvBuf, sizeof(rcvBuf),
		[&done, con = clientSideSession](const Error& ec, size_t transfered)
	{
		CHECK_CZSPAS_EQUAL(ConnectionClosed, ec);
		CHECK(0 == transfered);
		done.notify();
	});

	done.wait();
}

//
// Successfully cancelling an asynchronous send operation is hard in practice, since most of the time a socket is marked
// as ready to send by the OS.
// The only feasible way to correctly test the cancel in this case is to do a cancel right after the send from the 
// Service thread itself, so the Reactor doesn't have a chance to run.
TEST_CASE("Socket_asyncSendSome_cancel")
{
	ServiceThread ioth(true, true, true);

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	Semaphore done;
	ac->acceptor.asyncAccept(serverSideSession->sock, [&done, this_=ac, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS(ec);
		static char sndBuf[4];
		// Do the two calls here inside the Service thread, so the Reactor doesn't have the chance to initiate the
		// send
		con->sock.asyncSendSome(sndBuf, sizeof(sndBuf), [&done, con](const Error& ec, size_t transfered)
		{
			CHECK_CZSPAS_EQUAL(Cancelled, ec);
			CHECK(0 == transfered);
			done.notify();
		});

		con->sock.cancel();
	});

	auto clientSideSession = std::make_shared<Session<>> (ioth.service);
	auto ec = clientSideSession->sock.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS(ec);

	done.wait();
}

TEST_CASE("Socket_asyncSendSome_timeout")
{
	// #TODO: I can't think of a feasible way to test a send timeout, since most of the time a socket will be ready
	// to write.
	// Internally, the Reactor tries to do the send/recv before checking the timeout, so if the socket is always ready
	// to write, the send timeout is very hard to test.
}

TEST_CASE("Socket_asyncSendSome_peerDisconnect")
{
	ServiceThread ioth(true, true, true);

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	Semaphore done;
	ac->acceptor.asyncAccept(serverSideSession->sock, [&done, this_=ac, con = serverSideSession](const Error& ec) mutable
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
	clientSideSession->sock.asyncSendSome(sndBuf, sizeof(sndBuf), 
		[&done, &sndBuf, con = clientSideSession](const Error& ec, size_t transfered)
	{
		// It might happen we detect the connection as closed right away, or the OS still considers some data was sent
		if (ec.code == Error::Code::ConnectionClosed)
		{
			CHECK(0 == transfered);
			done.notify();
		}
		else
		{
			CHECK_CZSPAS(ec);
			CHECK(transfered > 0);
			// Try another send. This one should already fail
			con->sock.asyncSendSome(sndBuf, sizeof(sndBuf), 
				[&done, con](const Error& ec, size_t transfered)
			{
				CHECK_CZSPAS_EQUAL(ConnectionClosed, ec);
				CHECK(0 == transfered);
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
	session->acceptor.asyncAccept(serverSideSession->sock, [&numAccepts, this_ = session, con = serverSideSession](const Error& ec) mutable
	{
		CHECK_CZSPAS(ec);
		++numAccepts;
		Socket_multiple_connections_acceptorHelper(this_, numAccepts);
	});
}

TEST_CASE("Socket_multiple_connections")
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
			ServiceThread ioth(true, true, true);

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

	CHECK(numThreads*itemsPerThread == numDone.load());
}

//! Tests a big transfer, to make it can really handle size_t sizes.
// This is because sockets sends/receives only allow a 32-bits size, but the API puts together multiple socket
// calls to make it possible to send/receive data with a real size_t size.
TEST_CASE("Socket_bigTransfer", "[slow]")
{
	constexpr size_t bigbufsize = INTENSIVE_TEST ? (size_t(INT_MAX) + 1) : (size_t(INT_MAX) / 4);

	auto serverth = std::thread( [bigbufsize]{
		ServiceThread ioth(false, false, false);
		auto bigbuf = std::shared_ptr<char>(new char[bigbufsize], [](char* p) { delete[] p; });

		Acceptor acceptor(ioth.service);
		acceptor.listen(SERVER_PORT);
		auto sock = std::make_shared<Socket>(ioth.service);
		auto ec = acceptor.accept(*sock);
		CHECK_CZSPAS(ec);
		Semaphore done;
		asyncReceive(*sock, bigbuf.get(), bigbufsize, [&, sock, bigbuf](const Error& ec, size_t transfered)
		{
			CHECK_CZSPAS(ec);
			CHECK(bigbufsize == transfered);
			auto ptr = bigbuf.get();
			for (size_t i = 0; i < bigbufsize; i++)
			{
				CHECK(int(char(i)) == int(ptr[i]));
			}
			done.notify();
		});

		ioth.run();
		ioth.finish();
		done.wait();
	});

	auto clientth = std::thread( [bigbufsize]{
		ServiceThread ioth(false, false, false);
		auto bigbuf = std::shared_ptr<char>(new char[bigbufsize], [](char* p) { delete[] p; });
		auto ptr = bigbuf.get();
		for (size_t i = 0; i < bigbufsize; i++)
			ptr[i] = (char)i;

		auto sock = std::make_shared<Socket>(ioth.service);
		auto ec = sock->connect("127.0.0.1", SERVER_PORT);
		CHECK_CZSPAS(ec);
		Semaphore done;
		asyncSend(*sock, bigbuf.get(), bigbufsize, [&, sock, bigbuf](const Error& ec, size_t transfered)
		{
			CHECK_CZSPAS(ec);
			CHECK(bigbufsize == transfered);
			done.notify();
		});
		ioth.run();
		ioth.finish();
		done.wait();
	});

	serverth.join();
	clientth.join();
}

TEST_CASE("Socket_sendSome_receiveSome_ok")
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
	auto done = sender.sendSome("Hello World!", strlen(outBuf), ec);
	CHECK(strlen(outBuf) == done);
	CHECK_CZSPAS(ec);

	char inBuf[64];
	memset(inBuf, 0, sizeof(inBuf));
	done = receiver.receiveSome(inBuf, sizeof(inBuf), ec);
	CHECK(strlen(outBuf) == done);
	CHECK_CZSPAS(ec);
	CHECK(std::string(outBuf) == inBuf);
}

TEST_CASE("Socket_receiveSome_timeout")
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

	// Test receive timeout, since there is no more data to read
	char inBuf[1];
	auto start = getTime();
	auto done = receiver.receiveSome(inBuf, sizeof(inBuf), 20, ec);
	CHECK_DELTA_TIME(start, getTime(), 20ms, 200ms);
	CHECK(0 == done);
	CHECK_CZSPAS_EQUAL(Timeout, ec);
}

TEST_CASE("Socket_receiveSome_disconnect")
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

	sender._forceClose(false);
	char inBuf[1];
	auto done = receiver.receiveSome(inBuf, sizeof(inBuf), ec);
	CHECK(0 == done);
	CHECK_CZSPAS_EQUAL(ConnectionClosed, ec);
}

TEST_CASE("Socket_receiveSome_error")
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

	// Close our own socket before sending, just to test error detection
	auto h = receiver.getHandle(); // Copying to a local, since detail::utils::closeSocket clears the input
	detail::utils::closeSocket(h);
	char inBuf[1];
	auto done = receiver.receiveSome(inBuf, sizeof(inBuf), ec);
	CHECK(0 == done);
	CHECK_CZSPAS_EQUAL(Other, ec);
}

TEST_CASE("Socket_sendSome_timeout")
{
	// #TODO : No idea how to test this one :(
}

TEST_CASE("Socket_sendSome_disconnect")
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
	receiver._forceClose(false);

	// Even thought the peer was closed, a send can still say it succeeded, so we need to loop until it eventually
	// fails to test the desired code path.
	size_t done;
	while (!ec)
	{
		char outBuf[2];
		done = sender.sendSome(outBuf, sizeof(outBuf), ec);
		if (!ec)
			CHECK(2 == done);
	}
	CHECK(0 == done);
	CHECK_CZSPAS_EQUAL(Other, ec);
}

TEST_CASE("Socket_sendSome_error")
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

	// Close our own socket before sending, just to test error detection
	auto h = sender.getHandle(); // Copying to a local, since detail::utils::closeSocket clears the input
	detail::utils::closeSocket(h);
	char outBuf[1];
	auto done = sender.sendSome(outBuf, sizeof(outBuf), ec);
	CHECK(0 == done);
	CHECK_CZSPAS_EQUAL(Other, ec);
}

TEST_CASE("receive_ok")
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

	auto senderFt = std::async(std::launch::async, [&sender]
	{
		// To understand that last string, see:
		// http://stackoverflow.com/questions/164168/how-do-you-construct-a-stdstring-with-an-embedded-null
		std::vector<std::string> out{ "Hello", " ", "World", "!", std::string("\0", 1)};
		for (auto&& s : out)
		{
			Error ec;
			auto transfered = send(sender, s.c_str(), s.size(), ec);
			CHECK(s.size() == transfered);
			// Make a small pause, so we can test the receiver receiving it in parts.
			std::this_thread::sleep_for(20ms);
		}
	});

	char in[128];
	auto expected = strlen("Hello World!") + 1;
	auto transfered = receive(receiver, in, expected, ec);
	CHECK(expected == transfered);
	CHECK(std::string("Hello World!") == in);
	CHECK_CZSPAS(ec);
	senderFt.get();
}

TEST_CASE("receive_timeout")
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

	auto senderFt = std::async(std::launch::async, [&sender]
	{
		// To understand that last string, see:
		// http://stackoverflow.com/questions/164168/how-do-you-construct-a-stdstring-with-an-embedded-null
		std::vector<std::string> out{ "Hello", " ", "World", "!", std::string("\0", 1)};
		for (auto&& s : out)
		{
			Error ec;
			auto transfered = send(sender, s.c_str(), s.size(), ec);
			CHECK(s.size() == transfered);
			// Make a small pause, so we can test the receiver receiving it in parts.
			std::this_thread::sleep_for(20ms);
		}
	});

	char in[128];
	auto expected = strlen("Hello World!") + 1;
	// By passing an expected size bigger than what the sender will send, we should get all the data sent,
	// but get a Timeout error.
	auto transfered = receive(receiver, in, sizeof(in), 500, ec);
	CHECK(expected == transfered);
	CHECK(std::string("Hello World!") == in);
	CHECK_CZSPAS_EQUAL(Timeout, ec);
	senderFt.get();
}

TEST_CASE("receive_peerDisconnect")
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

	auto senderFt = std::async(std::launch::async, [&sender]
	{
		// To understand that last string, see:
		// http://stackoverflow.com/questions/164168/how-do-you-construct-a-stdstring-with-an-embedded-null
		std::vector<std::string> out{ "Hello", " ", "World", "!", std::string("\0", 1)};
		for (auto&& s : out)
		{
			Error ec;
			auto transfered = send(sender, s.c_str(), s.size(), ec);
			CHECK(s.size() == transfered);
			// Make a small pause, so we can test the receiver receiving it in parts.
			std::this_thread::sleep_for(10ms);
		}

		sender._forceClose(true);
	});

	char in[128];
	auto expected = strlen("Hello World!") + 1;
	// By passing an expected size bigger than what the sender will send, we should get all the data sent,
	// but also a Timeout error;
	auto transfered = receive(receiver, in, sizeof(in), 500, ec);
	CHECK(expected == transfered);
	CHECK(std::string("Hello World!") == in);
	CHECK_CZSPAS_EQUAL(ConnectionClosed, ec);
	senderFt.get();
}

//
//
// Throw exceptions from user handlers
void exception_safety_setupAccept(cz::spas::Acceptor& ac, ZeroSemaphore& sem, bool& cancelled)
{
	auto serverSideSession = std::make_shared<Session<>>(ac.getService());
	ac.asyncAccept(serverSideSession->sock, [&ac, &sem, &cancelled, serverSideSession](const Error& ec)
	{
		if (ec)
		{
			if (ec.code == Error::Code::Cancelled)
			{
				cancelled = true;
				return;
			}
			else
			{
				CHECK(0); // always fail if it gets here
			}

		}
		else
		{
			sem.decrement();
		}

		exception_safety_setupAccept(ac, sem, cancelled);
	});
}

TEST_CASE("exception_safety")
{
	Service service;

	int const numClients = 4;

	// Setup the acceptor before starting the Service, so the service has work
	spas::Acceptor acceptor(service);
	auto ec = acceptor.listen(SERVER_PORT);
	CHECK_CZSPAS(ec);
	ZeroSemaphore acceptSem(numClients);
	bool cancelled = false;
	exception_safety_setupAccept(acceptor, acceptSem, cancelled);

	int handledCount = 0;
	auto ioth = std::thread([&service, &handledCount]
	{
		while (true)
		{
			try
			{
				service.run();
				return; // Normal return
			}
			catch (std::exception& exc)
			{
				handledCount++;
				CHECK(std::string("Testing exception") == exc.what());
			}
		}
	});

	std::vector<std::unique_ptr<Session<bool>>> clients;
	ZeroSemaphore sem2;
	for (int i = 0; i < numClients; i++)
	{
		clients.push_back(std::make_unique<Session<bool>>(service));
		sem2.increment();
		clients.back()->sock.asyncConnect("127.0.0.1", SERVER_PORT, [&sem2, c = clients.back().get()](const spas::Error& ec)
		{
			sem2.decrement();
			CHECK_CZSPAS(ec);
			throw std::runtime_error("Testing exception");
		});
	}

	sem2.wait();
	acceptSem.wait();
	service.post([&acceptor]
	{
		acceptor.cancel(); // The acceptor is the only one chaining operations, so canceling should cause the Service to run out of work
	});
	ioth.join();
	CHECK(numClients == handledCount);
	CHECK(cancelled);
}

struct ResolverSession : std::enable_shared_from_this<ResolverSession>
{
	ResolverSession(Service& service)
		: resolver(service)
	{
	}

	Resolver resolver;
};

TEST_CASE("asyncConnect", "[Resolver]")
{
	TEST_LOG("");

	ServiceThread ioth(false, false, false);
	ioth.run();

	SECTION("Success")
	{
		auto resolverSession = std::make_shared<ResolverSession>(ioth.service);
		resolverSession->resolver.asyncResolve("example.com", [resolverSession](const Error& ec, std::string ip)
		{
			TEST_LOG("Test 1");
			CHECK(ec.code == Error::Code::Success);
		});
	}

	SECTION("Host not found")
	{
		auto resolverSession = std::make_shared<ResolverSession>(ioth.service);
		resolverSession->resolver.asyncResolve("example.coom", [resolverSession](const Error& ec, std::string ip)
		{
			TEST_LOG("Test 2");
			CHECK(ec.code == Error::Code::HostNotFound);
		});
	}

}

