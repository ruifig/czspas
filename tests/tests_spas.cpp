#include "testsPCH.h"

using namespace cz;
using namespace spas;

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

struct TestServer
{
	Service io;
	std::thread th;
	Acceptor* acceptor;
	Semaphore accepted;
	ZeroSemaphore pendingOps;
	std::vector<std::shared_ptr<Socket>> socks;
	UnitTest::Timer timer;
	bool detectDisconnect;

	explicit TestServer(bool detectDisconnect=false)
	{
		this->detectDisconnect = detectDisconnect;
		timer.Start();
		th = std::thread([this]
		{
			io.run();
		});

		auto ac = std::make_shared<Acceptor>(io);
		acceptor = ac.get();
		CHECK_CZSPAS(ac->listen(SERVER_PORT, 100));
		doAccept(ac, detectDisconnect);
	}

	~TestServer()
	{
		io.post([ac=acceptor]
		{
			ac->cancel();
		});

		if (!detectDisconnect)
		{
			io.post([&]
			{
				for (auto&& s : socks)
					s->cancel();
			});
		}

		pendingOps.wait();
		io.stop();
		if (th.joinable())
			th.join();
	}

	void doAccept(std::shared_ptr<Acceptor> ac, bool detectDisconnect = false)
	{
		pendingOps.increment();
		auto sock = std::make_shared<Socket>(io);
		ac->asyncAccept(*sock, -1, [this, ac, sock, detectDisconnect](const Error& ec)
		{
			pendingOps.decrement();
			if (ec.code == Error::Code::Cancelled)
				return;
			CHECK_CZSPAS(ec);
			socks.push_back(sock);
			accepted.notify();
			if (detectDisconnect)
				setDisconnectDetection(sock);
			doAccept(ac, detectDisconnect);
		});
	}

	void setDisconnectDetection(std::shared_ptr<Socket> sock)
	{
		static char buf[1];
		pendingOps.increment();
		sock->asyncReceiveSome(buf, 1, -1, [this, sock](const Error& ec, size_t transfered)
		{
			pendingOps.decrement();
			CHECK_CZSPAS_EQUAL(ConnectionClosed, ec);
			socks.erase(std::remove(socks.begin(), socks.end(), sock), socks.end());
		});
	}

	void waitForAccept()
	{
		accepted.wait();
	}
	
	auto get_threadid() const
	{
		return th.get_id();
	}

};

SUITE(CZSPAS)
{

//////////////////////////////////////////////////////////////////////////
// Acceptor tests
//////////////////////////////////////////////////////////////////////////

// Checks behavior for a simple listen
TEST(Acceptor_listen_ok)
{
	Service io;
	Acceptor ac(io);
	auto ec = ac.listen(SERVER_PORT, 1);
	CHECK_CZSPAS(ec);
}

// Checks behavior when trying to listen on an invalid port
TEST(Acceptor_listen_failure)
{
	Service io;
	Acceptor ac(io);
	auto ec = ac.listen(SERVER_UNUSABLE_PORT, 1);
	CHECK_CZSPAS_EQUAL(Other, ec);
}

// Tests the accept timeout behavior
// Because internally the timeout is split in two fields (microseconds and seconds), we need to test something below
// 1 second, and something above, to make sure the split is done correctly
TEST(Acceptor_accept_timeout)
{
	Service io;
	Acceptor ac(io);
	auto ec = ac.listen(SERVER_PORT, 1);
	CHECK_CZSPAS(ec);

	Socket s(io);
	UnitTest::Timer timer;
	timer.Start();
	ec = ac.accept(s, 50);
	CHECK_CLOSE(50, timer.GetTimeInMs(), 20);
	CHECK_CZSPAS_EQUAL(Timeout, ec);

	timer.Start();
	ec = ac.accept(s, 1050);
	CHECK_CLOSE(1050, timer.GetTimeInMs(), 20);
	CHECK_CZSPAS_EQUAL(Timeout, ec);
}


// What this test tests doesn't make sense in a real use case, but nevertheless it checks some different code paths.
// It does the following:
//		- Thread 1 does a synchronous accept (it blocks waiting for the accept to finish)
//		- Thread 2 does an explicit close on the acceptor socket,
//		- Thread 1 detects the broken accept call and gives an error.
// The reason this is not a real use case is because there is no need to have an API to break out of a synchronous accept call.
//
#if 0
TEST(Acceptor_accept_break)
{
	Service io;
	Acceptor ac(io);
	auto ec = ac.listen(SERVER_PORT, 1);
	CHECK_CZSPAS(ec);

	auto ft1 = std::async(std::launch::async, [&ac, &io]
	{
		Socket s(io);
		auto ec = ac.accept(s);
		CHECK_CZSPAS_EQUAL(Other, ec);
	});

	auto ft2 = std::async(std::launch::async, [&ac]
	{
		// Give it some time for the other thread to start the accept
		//
		UnitTest::TimeHelpers::SleepMs(200);

		// Closing the socket on our own, to cause the accept to break
		// Initially I was calling spas::detail::utils::closeSocket(ac.getHandle()), which works fine on Windows.
		// It does a shutdown with SD_BOTH on Windows, and SD_RDWR on Linux, but it seems on Linux, using a shutdown with
		// SD_RDWR doesn't cause the ::select used internally by Acceptor::accept to break. It hangs forever.
        // So, I need to do a manual shutdown with SHUT_RD
#if _WIN32
		ac._forceClose(false);
#else
		::shutdown(ac.getHandle(), SHUT_RD);
#endif
	});

	ft1.get();
	ft2.get();
}
#endif

//////////////////////////////////////////////////////////////////////////
// Socket tests
//////////////////////////////////////////////////////////////////////////

TEST(Socket_connect_ok)
{
	Service io;
	Acceptor ac(io);
	auto ec = ac.listen(SERVER_PORT, 1);
	CHECK_CZSPAS(ec);

	auto ft = std::async(std::launch::async, [&io]
	{
		UnitTest::TimeHelpers::SleepMs(10);
		Socket s(io);
		auto ec = s.connect("127.0.0.1", SERVER_PORT);
		CHECK_CZSPAS(ec);
	});

	Socket s(io);
	ac.accept(s, 1000);
	ft.get();
}

TEST(Socket_connect_failure)
{
	Service io;
	Socket s(io);
	auto ec = s.connect("127.0.0.1", SERVER_PORT);
	CHECK_CZSPAS_EQUAL(Other, ec);
}

TEST(Socket_asyncConnect_ok)
{
	Service io;

	Socket serverSide(io);
	Semaphore readyToAccept;
	auto ft = std::async(std::launch::async, [&]
	{
		Acceptor ac(io);
		auto ec = ac.listen(SERVER_PORT, 1);
		CHECK_CZSPAS(ec);
		readyToAccept.notify();
		ec = ac.accept(serverSide, 1000);
		CHECK_CZSPAS(ec);
	});

	Socket s(io);
	Semaphore done;

	// This is needed, since it is possible we take longer than expected to get to the accept call
	// done in the std::async, therefore causing a time in the asyncConnect.
	readyToAccept.wait();

	auto allowedThread = std::this_thread::get_id();
	UnitTest::Timer timer;
	timer.Start();
	s.asyncConnect("127.0.0.1", SERVER_PORT, -1, [&](const Error& ec)
	{
		CHECK_CZSPAS(ec);
		CHECK(std::this_thread::get_id() == allowedThread);
		io.stop(); // stop the service, to finish this test
		done.notify();
	});

	io.run();
	ft.get();
	done.wait(); // To make sure the asyncConnect gets called
}

TEST(Socket_asyncConnect_timeout)
{
	Service io;

	Socket s(io);
	Semaphore done;
	UnitTest::Timer timer;
	timer.Start();
	int timeoutMs = 200;
	auto allowedThread = std::this_thread::get_id();
	s.asyncConnect("127.0.0.1", SERVER_PORT, timeoutMs, [&](const Error& ec)
	{
		CHECK_CZSPAS_EQUAL(Timeout, ec);
		CHECK_CLOSE(timeoutMs, timer.GetTimeInMs(), 100);
		CHECK(std::this_thread::get_id() == allowedThread);
		io.stop(); // stop the service, to finish this test
		done.notify();
	});
	io.run();
	done.wait(); // To make sure the asyncConnect gets called
}

TEST(Socket_asyncConnect_cancel)
{
	Service io;

	Socket s(io);
	Semaphore done;
	UnitTest::Timer timer;
	timer.Start();
	auto allowedThread = std::this_thread::get_id();
	s.asyncConnect("127.0.0.1", SERVER_PORT, -1, [&](const Error& ec)
	{
		CHECK_CZSPAS_EQUAL(Cancelled, ec);
		CHECK(std::this_thread::get_id() == allowedThread);
		io.stop();
		done.notify();
	});
	s.cancel();
	io.run();
	done.wait(); // To make sure the asyncConnect gets called
}

TEST(Acceptor_asyncAccept_ok)
{
	Service io;

	auto ioth = std::thread([&io]
	{
		io.run();
	});

	Semaphore done;
	Socket serverSide(io);
	Acceptor ac(io);
	auto ec = ac.listen(SERVER_PORT, 1);
	CHECK_CZSPAS(ec);
	ac.asyncAccept(serverSide, 1000, [&](const Error& ec)
	{
		CHECK_CZSPAS(ec);
		CHECK(std::this_thread::get_id() == ioth.get_id());
		done.notify();
	});

	Socket s(io);
	s.asyncConnect("127.0.0.1", SERVER_PORT, 1000, [&](const Error& ec)
	{
		CHECK_CZSPAS(ec);
		CHECK(std::this_thread::get_id() == ioth.get_id());
		done.notify();
	});

	done.wait();
	done.wait();
	io.stop();
	ioth.join();
}

TEST(Acceptor_asyncAccept_cancel)
{
	Service io;

	auto ioth = std::thread([&io]
	{
		io.run();
	});

	Semaphore done;
	Socket serverSide(io);
	Acceptor ac(io);
	auto ec = ac.listen(SERVER_PORT, 1);
	CHECK_CZSPAS(ec);
	ac.asyncAccept(serverSide, 1000, [&](const Error& ec)
	{
		CHECK_CZSPAS_EQUAL(Cancelled, ec);
		CHECK(std::this_thread::get_id() == ioth.get_id());
		done.notify();
	});

	io.post([&]
	{
		ac.cancel();
	});

	done.wait();
	io.stop();
	ioth.join();
}

TEST(Socket_asyncReceiveSome_ok)
{
	TestServer server;
	Semaphore done;

	Socket s(server.io);
	CHECK_CZSPAS(s.connect("127.0.0.1", SERVER_PORT));
	char buf[6];
	server.waitForAccept();

	// Test receiving all the data in one call
	CHECK_EQUAL(6, ::send(server.socks[0]->getHandle(), "Hello", 6, 0));
	s.asyncReceiveSome(buf, sizeof(buf), -1, [&](const Error& ec, size_t transfered)
	{
		CHECK(std::this_thread::get_id() == server.get_threadid());
		CHECK_EQUAL(sizeof(buf), transfered);
		CHECK_EQUAL("Hello", buf);
		done.notify();
	});
	done.wait();

	// Test receiving all the data in two calls
	memset(buf, 0, sizeof(buf));
	CHECK_EQUAL(6, ::send(server.socks[0]->getHandle(), "Hello", 6, 0));
	s.asyncReceiveSome(&buf[0], 2, -1, [&](const Error& ec, size_t transfered)
	{
		CHECK(std::this_thread::get_id() == server.get_threadid());
		CHECK_EQUAL(2, transfered);
		s.asyncReceiveSome(&buf[2], 4, -1, [&](const Error& ec, size_t transfered)
		{
			CHECK_EQUAL(4, transfered);
			CHECK_EQUAL("Hello", buf);
			done.notify();
		});
		done.notify();
	});

	done.wait();
	done.wait();
}

TEST(Socket_asyncReceiveSome_cancel)
{
	TestServer server;
	Semaphore done;

	Socket s(server.io);
	CHECK_CZSPAS(s.connect("127.0.0.1", SERVER_PORT));
	char buf[6];
	server.waitForAccept();
	s.asyncReceiveSome(buf, sizeof(buf), -1, [&](const Error& ec, size_t transfered)
	{
		CHECK(std::this_thread::get_id() == server.get_threadid());
		CHECK_EQUAL(0, transfered);
		CHECK_CZSPAS_EQUAL(Cancelled, ec);
		done.notify();
	});
	server.io.post([&s]
	{
		s.cancel();
	});
	done.wait();
}

TEST(Socket_asyncReceiveSome_timeout)
{
	TestServer server;
	Semaphore done;

	Socket s(server.io);
	CHECK_CZSPAS(s.connect("127.0.0.1", SERVER_PORT));
	char buf[6];
	server.waitForAccept();
	auto start = server.timer.GetTimeInMs();
	s.asyncReceiveSome(buf, sizeof(buf), 100, [&](const Error& ec, size_t transfered)
	{
		CHECK_CLOSE(100, server.timer.GetTimeInMs() - start, 100);
		CHECK(std::this_thread::get_id() == server.get_threadid());
		CHECK_EQUAL(0, transfered);
		CHECK_CZSPAS_EQUAL(Timeout, ec);
		done.notify();
	});
	done.wait();
}

TEST(Socket_asyncReceiveSome_peerDisconnect)
{
	TestServer server;
	Semaphore done;

	Socket s(server.io);
	CHECK_CZSPAS(s.connect("127.0.0.1", SERVER_PORT));
	char buf[6];
	server.waitForAccept();
	s.asyncReceiveSome(buf, sizeof(buf), -1, [&](const Error& ec, size_t transfered)
	{
		CHECK(std::this_thread::get_id() == server.get_threadid());
		CHECK_EQUAL(0, transfered);
		CHECK_CZSPAS_EQUAL(ConnectionClosed, ec);
		done.notify();
	});
	server.io.post([&]
	{
		server.socks[0]->_forceClose(false);
	});
	done.wait();
}

TEST(Socket_asyncSendSome_ok)
{
	TestServer server;
	Semaphore done;

	Socket s(server.io);
	CHECK_CZSPAS(s.connect("127.0.0.1", SERVER_PORT));
	char buf[6];
	server.waitForAccept();

	// Test sending all the data with 1 call
	server.socks[0]->asyncSendSome("Hello", 6, -1, [&](const Error& ec, size_t transfered)
	{
		CHECK(std::this_thread::get_id() == server.get_threadid());
		CHECK_CZSPAS(ec);
		CHECK_EQUAL(6, transfered);
		done.notify();
	});
	s.asyncReceiveSome(buf, sizeof(buf), -1, [&](const Error& ec, size_t transfered)
	{
		CHECK(std::this_thread::get_id() == server.get_threadid());
		CHECK_EQUAL(sizeof(buf), transfered);
		CHECK_EQUAL("Hello", buf);
		done.notify();
	});
	done.wait();
	done.wait();

	// Test send the data in two calls
	server.socks[0]->asyncSendSome("He", 2, -1, [&](const Error& ec, size_t transfered)
	{
		CHECK_CZSPAS(ec);
		CHECK_EQUAL(2, transfered);
		done.notify();
		server.socks[0]->asyncSendSome("llo", 4, -1, [&](const Error& ec, size_t transfered)
		{
			CHECK_CZSPAS(ec);
			CHECK_EQUAL(4, transfered);
			done.notify();
		});
	});
	done.wait();
	done.wait();

	memset(buf, 0, sizeof(buf));
	s.asyncReceiveSome(buf, sizeof(buf), -1, [&](const Error& ec, size_t transfered)
	{
		CHECK(std::this_thread::get_id() == server.get_threadid());
		CHECK_EQUAL(sizeof(buf), transfered);
		CHECK_EQUAL("Hello", buf);
		done.notify();
	});
	done.wait();
}

TEST(Socket_asyncSendSome_cancel)
{
	TestServer server;
	Semaphore done;

	Socket s(server.io);
	CHECK_CZSPAS(s.connect("127.0.0.1", SERVER_PORT));
	server.waitForAccept();

	constexpr size_t bigbufsize = size_t(INT_MAX);
	auto bigbuf = std::unique_ptr<char[]>(new char[bigbufsize]);

	// NOTE: By sending a really big buffer, the IODemux thread will be busy on the ::send, so our Service thread
	// has time to do the cancel
	std::atomic<bool> cancelDone(false);
	s.asyncSendSome(bigbuf.get(), bigbufsize, -1, [&](const Error& ec, size_t transfered)
	{
		CHECK(cancelDone.load() == true); // make sure the cancel ran before this, otherwise the test doesn't make sense
		CHECK_CZSPAS_EQUAL(Cancelled, ec);
		done.notify();
	});
	server.io.post([&]
	{
		cancelDone = true;
		s.cancel();
	});

	done.wait();
}

//
// This test checks that a timeout on a send is actually very unlikely to happen.
// This is because both the timeout calculations and the ::send (and ::recv) calls are done on the IODemux threads,
// and so, once the call to ::send starts, the operation will not timeout even if it takes much longer to complete
// than the specified timeout
TEST(Socket_asyncSendSome_timeout)
{
	TestServer server;
	Semaphore done;

	Socket s(server.io);
	CHECK_CZSPAS(s.connect("127.0.0.1", SERVER_PORT));
	server.waitForAccept();

	constexpr size_t bigbufsize = size_t(INT_MAX)/4;
	auto bigbuf = std::unique_ptr<char[]>(new char[bigbufsize]);

	std::atomic<bool> cancelDone(false);
	auto startTime = server.timer.GetTimeInMs();
	constexpr int timeoutMs = 1;
	s.asyncSendSome(bigbuf.get(), bigbufsize, timeoutMs, [&](const Error& ec, size_t transfered)
	{
		CHECK_CZSPAS_EQUAL(Success, ec);
		// Make sure the operation took longer than the timeout
		auto delta = server.timer.GetTimeInMs() - startTime;
		CHECK(delta > timeoutMs);
		done.notify();
	});
	done.wait();
}


// Create and destroy lots of connections really fast, to make sure we can set lingering off
TEST(Socket_multiple_connections)
{
	TestServer server(true);
	Semaphore done;

	int todo = 70000;
	int count = 0;
	while (todo--)
	{
		count++;
		Socket s(server.io);
		auto res = s.connect("127.0.0.1", SERVER_PORT);
		if (res)
		{
			CHECK_CZSPAS(res);
		}
		//detail::utils::setBlocking(s.getHandle(), true);
		s.setLinger(true, 0);
		//printf("%d: Closed at %s\n", (int)s.getHandle(), __FUNCTION__);
		s._forceClose(false);
	}
	//UnitTest::TimeHelpers::SleepMs(100000000);
}

#if 0

TEST(Dummy)
{
	{
		TestServer server;
		Semaphore done;

		Socket s(server.io);
		CHECK_CZSPAS(s.connect("127.0.0.1", SERVER_PORT));
		char buf[6];
		server.waitForAccept();

		s.asyncReceiveSome(buf, sizeof(buf), 10000, [&](const Error& ec, size_t transfered)
		{
			CHECK(std::this_thread::get_id() == server.get_threadid());
			CHECK_EQUAL(sizeof(buf), transfered);
			CHECK_EQUAL("Hello", buf);
			done.notify();
		});
		UnitTest::TimeHelpers::SleepMs(1000);
		//::shutdown(s.getHandle(), SD_BOTH);
		::closesocket(s.getHandle());
		done.wait();

		server.socks[0]->asyncReceiveSome(buf, sizeof(buf), 10000, [&](const Error& ec, size_t transfered)
		{
			CHECK(std::this_thread::get_id() == server.get_threadid());
			CHECK_EQUAL(sizeof(buf), transfered);
			CHECK_EQUAL("Hello", buf);
			done.notify();
		});
		done.wait();
		UnitTest::TimeHelpers::SleepMs(1000);

		server.socks[0]->asyncReceiveSome(buf, sizeof(buf), 10000, [&](const Error& ec, size_t transfered)
		{
			CHECK(std::this_thread::get_id() == server.get_threadid());
			CHECK_EQUAL(sizeof(buf), transfered);
			CHECK_EQUAL("Hello", buf);
			done.notify();
		});

		UnitTest::TimeHelpers::SleepMs(1000);
		//::shutdown(s.getHandle(), SD_BOTH);
		//::shutdown(server.socks[0]->getHandle(), SD_BOTH);
		done.wait();
	}
}

TEST(Socket_asyncSendSome_timeout)
{
	TestServer server;
	Semaphore done;

	Socket s(server.io);
	CHECK_CZSPAS(s.connect("127.0.0.1", SERVER_PORT));
	char buf[6];
	server.waitForAccept();

	s.asyncReceiveSome(buf, sizeof(buf), 5000, [&](const Error& ec, size_t transfered)
	{
		CHECK(std::this_thread::get_id() == server.get_threadid());
		CHECK_EQUAL(sizeof(buf), transfered);
		CHECK_EQUAL("Hello", buf);
		done.notify();
	});

	constexpr size_t bigbufsize = size_t(INT_MAX)+1;
	auto bigbuf = std::unique_ptr<char[]>(new char[bigbufsize]);

	// Test sending all the data with 1 call
	UnitTest::TimeHelpers::SleepMs(1000);
	//::closesocket(server.socks[0]->getHandle());
	::shutdown(s.getHandle(), SD_BOTH);
	::closesocket(s.getHandle());
	//::shutdown(server.socks[0]->getHandle(), SD_BOTH);
	done.wait();
	server.socks[0]->asyncSendSome(bigbuf.get(), bigbufsize, -1, [&](const Error& ec, size_t transfered)
	{
		CHECK(std::this_thread::get_id() == server.get_threadid());
		CHECK_CZSPAS(ec);
		CHECK_EQUAL(bigbufsize - 1, transfered);
		done.notify();
	});
	UnitTest::TimeHelpers::SleepMs(200);
	//::shutdown(s.getHandle(), SD_SEND);
	//::shutdown(server.socks[0]->getHandle(), SD_RECEIVE);
	done.wait();

	UnitTest::TimeHelpers::SleepMs(200);
	s.asyncReceiveSome(buf, sizeof(buf), -1, [&](const Error& ec, size_t transfered)
	{
		CHECK(std::this_thread::get_id() == server.get_threadid());
		CHECK_EQUAL(sizeof(buf), transfered);
		CHECK_EQUAL("Hello", buf);
		done.notify();
	});
	done.wait();
	done.wait();
}
#endif

}
