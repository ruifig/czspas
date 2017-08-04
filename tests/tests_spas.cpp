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

// Tests a call to Service::run when there is no work
TEST(Service_run_nowork)
{
	Service service;
	auto done = service.run();
	CHECK_EQUAL(0, done);
	CHECK(service.isStopped());
}

// Tests a call to Service::run when it has a dummy work to keep the run() call alive
// After an interval, it destroys the work item, which should cause the call to run() to unblock
TEST(Service_run_work_release)
{
	Service service;
	auto work = std::make_unique<Service::Work>(service); // Dummy work item

	auto ft = std::async(std::launch::async, [&work]
	{
		UnitTest::TimeHelpers::SleepMs(100);
		work.reset();
	});

	auto done = service.run();
	CHECK_EQUAL(0, done);
	CHECK(service.isStopped());
}

// Tests a call to Service::run when it has a dummy work to keep the run() call alive
// After an interval, it calls Service::stop . This should cause the call to run() to unblock even though the work item
// still exists
TEST(Service_run_work_stop)
{
	Service service;
	auto work = std::make_unique<Service::Work>(service); // Dummy work item

	auto ft = std::async(std::launch::async, [&service]
	{
		UnitTest::TimeHelpers::SleepMs(100);
		service.stop();
	});

	auto done = service.run();
	CHECK_EQUAL(0, done);
	CHECK(service.isStopped());
}

//////////////////////////////////////////////////////////////////////////
// Acceptor tests
//////////////////////////////////////////////////////////////////////////
// Checks behaviour for a simple listen
TEST(Acceptor_listen_ok)
{
	Service io;
	Acceptor ac(io);
	auto ec = ac.listen(SERVER_PORT);
	CHECK_CZSPAS(ec);
}

TEST(Acceptor_getLocalAddr)
{
	Service io;
	// Listening on all interfaces
	{
		Acceptor ac(io);
		auto ec = ac.listen(SERVER_PORT);
		CHECK_CZSPAS(ec);
		auto addr = ac.getLocalAddr();
		CHECK_EQUAL("0.0.0.0", addr.first);
		CHECK_EQUAL(SERVER_PORT, addr.second);
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
		CHECK_EQUAL("127.0.0.1", addr.first);
		CHECK_EQUAL(SERVER_PORT, addr.second);
	}
}

// Checks behaviour when trying to listen on an invalid port
TEST(Acceptor_listen_failure)
{
	Service io;
	Acceptor ac(io);
	auto ec = ac.listen(SERVER_UNUSABLE_PORT);
	CHECK_CZSPAS_EQUAL(Other, ec);
}

TEST(Acceptor_asyncAccept_ok)
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

// Tests the accept timeout behaviour
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

TEST(Acceptor_asyncAccept_timeout)
{
	ServiceThread ioth(true, true, true);

	auto ac = std::make_shared<AcceptorSession<>>(ioth.service, SERVER_PORT);

	Semaphore done;
	auto serverSideSession = std::make_shared<Session<>>(ioth.service);
	auto start = gTimer.GetTimeInMs();
	ac->acceptor.asyncAccept(serverSideSession->sock, 50,
		[&done, start, &ioth, this_=ac, con = serverSideSession](const Error& ec)
	{
		CHECK_CZSPAS_EQUAL(Timeout, ec);
		auto elapsed = gTimer.GetTimeInMs() - start;
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

TEST(Socket_getLocalAddr_getPeerAddr)
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

	CHECK_EQUAL("127.0.0.1", serverLocal.first);
	CHECK_EQUAL("127.0.0.1", serverPeer.first);
	CHECK_EQUAL("127.0.0.1", clientLocal.first);
	CHECK_EQUAL("127.0.0.1", clientPeer.first);

	CHECK_EQUAL(SERVER_PORT, serverLocal.second);
	CHECK_EQUAL(SERVER_PORT, clientPeer.second);
	CHECK(serverPeer.second != SERVER_PORT && serverPeer.second > 0);
	CHECK_EQUAL(serverPeer.second, clientLocal.second);
}

TEST(Socket_connect_failure)
{
	ServiceThread ioth(false, false, false);
	Socket clientSock(ioth.service);
	auto ec = clientSock.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS_EQUAL(Other,ec);
}

TEST(Socket_asyncConnect_ok)
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
	CHECK_EQUAL(2, done.getCount());
}

// Initially I was using "127.0.0.1" to test the asynchronous connect timeout or cancel, but it seems that on Linux
// it fails right away. Probably the kernel treats connections to the localhost in a different way, detecting
// right away that if a connect is not possible, without taking into consideration the timeout specified in
// the "select" function.
// On Windows, connect attempts to localhost still take into consideration the timeout.
// The solution is to try an connect to some external ip, like "254.254.254.254".
// This causes Linux to actually wait for the connect attempt.
// NOTE: WSL (Windows Subsystem for Linux) doesn't support non-blocking connects at this moment, so this test will fail
// although it seems in some systems, such has Windows
TEST(Socket_asyncConnect_cancel)
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

TEST(Socket_asyncConnect_timeout)
{
	ServiceThread ioth(true, true, true);

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
			CHECK_EQUAL(4, transfered);
			CHECK_EQUAL(0x11223344, *bufPtr);
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
			CHECK_EQUAL(4, transfered);
		});
	});

	done.wait();
}

TEST(Socket_asyncReceiveSome_cancel)
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
			CHECK_EQUAL(0, transfered);
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
	session->acceptor.asyncAccept(serverSideSession->sock, [&numAccepts, this_ = session, con = serverSideSession](const Error& ec) mutable
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

	CHECK_EQUAL(numThreads*itemsPerThread, numDone.load());
}

//! Tests a big transfer, to make it can really handle size_t sizes.
// This is because sockets sends/receives only allow a 32-bits size, but the API puts together multiple socket
// calls to make it possible to send/receive data with a real size_t size.
TEST(Socket_bigTransfer)
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
			CHECK_EQUAL(bigbufsize, transfered);
			auto ptr = bigbuf.get();
			for (size_t i = 0; i < bigbufsize; i++)
			{
				CHECK_EQUAL(int(char(i)), int(ptr[i]));
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
			CHECK_EQUAL(bigbufsize, transfered);
			done.notify();
		});
		ioth.run();
		ioth.finish();
		done.wait();
	});

	serverth.join();
	clientth.join();
}

TEST(Socket_sendSome_seceiveSome_ok)
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
	CHECK_EQUAL(strlen(outBuf), done);
	CHECK_CZSPAS(ec);

	char inBuf[64];
	memset(inBuf, 0, sizeof(inBuf));
	done = receiver.receiveSome(inBuf, sizeof(inBuf), ec);
	CHECK_EQUAL(strlen(outBuf), done);
	CHECK_CZSPAS(ec);
	CHECK_EQUAL(outBuf, inBuf);
}

TEST(Socket_receiveSome_timeout)
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
	auto start = gTimer.GetTimeInMs();
	auto done = receiver.receiveSome(inBuf, sizeof(inBuf), 20, ec);
	CHECK_CLOSE(20, gTimer.GetTimeInMs() - start, 200);
	CHECK_EQUAL(0, done);
	CHECK_CZSPAS_EQUAL(Timeout, ec);
}

TEST(Socket_receiveSome_disconnect)
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
	CHECK_EQUAL(0, done);
	CHECK_CZSPAS_EQUAL(ConnectionClosed, ec);
}

TEST(Socket_receiveSome_error)
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
	CHECK_EQUAL(0, done);
	CHECK_CZSPAS_EQUAL(Other, ec);
}

TEST(Socket_sendSome_timeout)
{
	// #TODO : No idea how to test this one :(
}

TEST(Socket_sendSome_disconnect)
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
			CHECK_EQUAL(2, done);
	}
	CHECK_EQUAL(0, done);
	CHECK_CZSPAS_EQUAL(Other, ec);
}

TEST(Socket_sendSome_error)
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
	CHECK_EQUAL(0, done);
	CHECK_CZSPAS_EQUAL(Other, ec);
}

TEST(receive_ok)
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
			CHECK_EQUAL(s.size(), transfered);
			// Make a small pause, so we can test the receiver receiving it in parts.
			UnitTest::TimeHelpers::SleepMs(20);
		}
	});

	char in[128];
	auto expected = strlen("Hello World!") + 1;
	auto transfered = receive(receiver, in, expected, ec);
	CHECK_EQUAL(expected, transfered);
	CHECK_EQUAL("Hello World!", in);
	CHECK_CZSPAS(ec);
	senderFt.get();
}

TEST(receive_timeout)
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
			CHECK_EQUAL(s.size(), transfered);
			// Make a small pause, so we can test the receiver receiving it in parts.
			UnitTest::TimeHelpers::SleepMs(20);
		}
	});

	char in[128];
	auto expected = strlen("Hello World!") + 1;
	// By passing an expected size bigger than what the sender will send, we should get all the data sent,
	// but get a Timeout error.
	auto transfered = receive(receiver, in, sizeof(in), 500, ec);
	CHECK_EQUAL(expected, transfered);
	CHECK_EQUAL("Hello World!", in);
	CHECK_CZSPAS_EQUAL(Timeout, ec);
	senderFt.get();
}

TEST(receive_peerDisconnect)
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
			CHECK_EQUAL(s.size(), transfered);
			// Make a small pause, so we can test the receiver receiving it in parts.
			UnitTest::TimeHelpers::SleepMs(10);
		}

		sender._forceClose(true);
	});

	char in[128];
	auto expected = strlen("Hello World!") + 1;
	// By passing an expected size bigger than what the sender will send, we should get all the data sent,
	// but also a Timeout error;
	auto transfered = receive(receiver, in, sizeof(in), 500, ec);
	CHECK_EQUAL(expected, transfered);
	CHECK_EQUAL("Hello World!", in);
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
TEST(exception_safety)
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
				CHECK_EQUAL("Testing exception", exc.what());
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
		acceptor.cancel(); // The acceptor is the only one chaining operations, so cancelling should cause the Service to run out of work
	});
	ioth.join();
	CHECK_EQUAL(numClients, handledCount);
	CHECK(cancelled);
}

}
