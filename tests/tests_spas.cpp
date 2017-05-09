#include "testsPCH.h"
using namespace cz;
using namespace spas;

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
// Internally, spas uses 2 sockets to allow interrupting a wsapoll/poll call.
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
// Because internally the timeout is split in two fields (microseconds and seconds, because it uses select), we need to
// test something below 1 second, and something above, to make sure the split is done correctly
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
	CHECK_CLOSE(50, timer.GetTimeInMs(), 200);
	CHECK_CZSPAS_EQUAL(Timeout, ec);

	timer.Start();
	ec = ac.accept(s, 1050);
	CHECK_CLOSE(1050, timer.GetTimeInMs(), 200);
	CHECK_CZSPAS_EQUAL(Timeout, ec);
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

#if 0

TEST(Socket_asyncConnect_timeout)
{
	Service io;

	Socket s(io);
	Semaphore done;
	UnitTest::Timer timer;
	timer.Start();
	int timeoutMs = 200;
	auto allowedThread = std::this_thread::get_id();
	// Initially I was using "127.0.0.1" to test the asynchronous connect timeout, but it seems that on linux
	// it fails right away. Probably the kernel treats connections to the localhost in a different way, detecting
	// right away that if a connect is not possible, without taking into consideration the timeout specified in
	// the "select" function.
	// On Windows, connect attempts to localhost still take into consideration the timeout.
	// The solution is to try an connect to some external ip, like "254.254.254.254". This causes Linux to
	// to actually wait for the connect attempt.
	s.asyncConnect("254.254.254.254", SERVER_PORT, timeoutMs, [&](const Error& ec)
	{
		CHECK_CZSPAS_EQUAL(Timeout, ec);
		// Need a big error of margin for the timeout, since it will depend on the load the computer had at the moment.
		CHECK_CLOSE(timeoutMs, timer.GetTimeInMs(), 1000);
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
	// Like explained in the test Socket_asyncConnect_timeout, using 254.254.254.254 instead of the localhost
	s.asyncConnect("254.254.254.254", SERVER_PORT, -1, [&](const Error& ec)
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
		::closesocket(server.socks[0]->getHandle());
		//server.socks[0]->_forceClose(false);
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


#if 0
TEST(Socket_asyncSendSome_cancel)
{
	TestServer server;
	Semaphore done;

	Socket s(server.io);
	CHECK_CZSPAS(s.connect("127.0.0.1", SERVER_PORT));
	server.waitForAccept();

	// NOTE: This unit test can actually fail without being an error, if the IODemux thread marks the send as ready
	// to execute before processing the cancel.
	// If the unit test doe indeed fail, consider removing it
	char buf[1024];
	std::atomic<bool> cancelDone(false);
	server.io.post([&]
	{
		s.asyncSendSome(buf, sizeof(buf), -1, [&](const Error& ec, size_t transfered)
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
	});

	done.wait();
}
#endif

//
// This test checks that a timeout on a send is actually very unlikely to happen.
// This is because sockets are ready to write most of the time (the OS buffers sent data). As such, the IODemux
// thread marks the send operation as ready to execute before any timeouts can occur.
// For example, even if the send itself takes longer than the timeout, it started before before the timeout and therefore
// is not marked as timed out.
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
	// Setting timeout to 0, to try and timeout right away.
	// A value of 0 is not something that would normally be used, and initially I was using 1 which works fine on Windows.
	// On Linux, it seems send completes way faster (due to smaller send buffers), and most of the time is shorter than 1 ms.
	constexpr int timeoutMs = 0;
	s.asyncSendSome(bigbuf.get(), bigbufsize, timeoutMs, [&](const Error& ec, size_t transfered)
	{
		// Make sure the operation took longer than the timeout
		// If that's not the case it means the send size needs to be increased so that this test makes sense
		auto delta = server.timer.GetTimeInMs() - startTime;
		CHECK(delta > timeoutMs);

		// This only makes sense if the operation time was longer than the timeout as explained above
		CHECK_CZSPAS_EQUAL(Success, ec);
		done.notify();
	});
	done.wait();
}



// Create and destroy lots of connections really fast, to make sure we can set lingering off
TEST(Socket_multiple_connections)
{
	TestServer server(true);

	int todo = 0;
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
		s.setLinger(true, 0);
		s._forceClose(false);
	}
}


static std::vector<size_t> gDumped;
ZeroSemaphore gDumpedPending;
size_t gDumpedTotal;

struct StandaloneHelper
{
	Service io;
	std::thread th;
	StandaloneHelper()
	{
		th = std::thread([this]
		{
			io.run();
		});
	}
	~StandaloneHelper()
	{
		th.join();
	}

	struct ClientReceiveConnection : std::enable_shared_from_this<ClientReceiveConnection>
	{
		explicit ClientReceiveConnection(Service& io, size_t bufsize)
			: sock(io)
			, bufsize(bufsize)
		{
			buf = std::unique_ptr<char[]>(new char[bufsize]);
		}

		~ClientReceiveConnection()
		{
			sock.getService().stop();
			CZSPAS_ASSERT(totalDone == expectedLen);
		}
		size_t bufsize=0;
		std::unique_ptr<char[]> buf;
		size_t expectedLen;
		size_t totalDone = 0;
		char next = 0;
		int intervalMs = 0;
		Socket sock;
		Error ec;
		void receiveHelper()
		{
			sock.asyncReceiveSome(buf.get(), bufsize, -1, [this_ = shared_from_this()](const Error& ec, size_t transfered)
			{
				this_->totalDone += transfered;
				CZSPAS_ASSERT(this_->totalDone <= this_->expectedLen);
				if (ec)
				{
					this_->ec = ec;
					return;
				}

				printf("%zu received: %zu/%zu\n", transfered, this_->totalDone, this_->expectedLen);
				// Check received data
				char* ptr = this_->buf.get();
				for (size_t i = 0; i < transfered; i++)
				{
					CHECK_EQUAL((int)this_->next, (int)ptr[i]);
					++this_->next;
				}

				if (this_->totalDone == this_->expectedLen)
					return;

				if (this_->intervalMs)
					std::this_thread::sleep_for(std::chrono::milliseconds(this_->intervalMs));
				this_->receiveHelper();
			});
		}
	};

	struct ServerSendConnection : std::enable_shared_from_this<ServerSendConnection>
	{
		explicit ServerSendConnection(Service& io, size_t bufsize)
			: sock(io)
			, acceptor(io)
			, bufsize(bufsize)
		{
			buf = std::unique_ptr<char[]>(new char[bufsize]);
		}
		~ServerSendConnection()
		{
			sock.getService().stop();
			CZSPAS_ASSERT(totalDone == expectedLen);
		}
		size_t bufsize=0;
		std::unique_ptr<char[]> buf;
		size_t expectedLen;
		size_t totalDone = 0;
		char next = 0;
		int intervalMs = 0;
		Socket sock;
		Acceptor acceptor;
		Error ec;
		void sendHelper()
		{
			auto todo = std::min(bufsize, expectedLen - totalDone);
			char* ptr = buf.get();
			for (size_t i = 0; i < todo; i++)
				ptr[i] = next++;

			sock.asyncSendSome(buf.get(), todo, -1, [this_ = shared_from_this()](const Error& ec, size_t transfered)
			{
				this_->totalDone += transfered;
				CZSPAS_ASSERT(this_->totalDone <= this_->expectedLen);
				if (ec)
				{
					this_->ec = ec;
					return;
				}

				printf("%zu sent: %zu/%zu\n", transfered, this_->totalDone, this_->expectedLen);

				if (this_->totalDone == this_->expectedLen)
				{
					// Setup a receive just to keep this alive until the client disconnects
					this_->sock.asyncReceiveSome(this_->buf.get(), 1, -1, [this_](const Error& ec, size_t transfered)
					{
					});
					return;
				}

				if (this_->intervalMs)
					std::this_thread::sleep_for(std::chrono::milliseconds(this_->intervalMs));
				this_->sendHelper();
			});
		}
	};
};

std::shared_ptr<StandaloneHelper> standaloneClientReceive(size_t len, int intervalMs, size_t bufsize)
{
	auto hlp = std::make_shared<StandaloneHelper>();
	auto con = std::make_shared<StandaloneHelper::ClientReceiveConnection>(hlp->io, bufsize);
	con->expectedLen = len;
	con->intervalMs = intervalMs;
	con->sock.asyncConnect("127.0.0.1", SERVER_PORT, -1, [con](const Error& ec)
	{
		CHECK_CZSPAS(ec);
		con->receiveHelper();
	});
	return hlp;
}

std::shared_ptr<StandaloneHelper> standaloneServerSend(size_t len, int intervalMs, size_t bufsize)
{
	auto hlp = std::make_shared<StandaloneHelper>();
	auto con = std::make_shared<StandaloneHelper::ServerSendConnection>(hlp->io, bufsize);
	con->expectedLen = len;
	con->intervalMs = intervalMs;
	auto ac = &con->acceptor;
	CHECK_CZSPAS(ac->listen(SERVER_PORT, 1));
	con->acceptor.asyncAccept(con->sock, -1, [con](const Error& ec)
	{
		CHECK_CZSPAS(ec);
		con->sendHelper();
	});

	return hlp;
}

TEST(standaloneClient_and_Server)
{
	{
		constexpr size_t expected = 1024 * 16;
		auto server = standaloneServerSend(expected, 0, 2000);
		auto client = standaloneClientReceive(expected, 1, 4096);
	}
}

TEST(asyncSend_big)
{
	TestServer server;
	Semaphore done;

	Socket s(server.io);
	CHECK_CZSPAS(s.connect("127.0.0.1", SERVER_PORT));
	server.waitForAccept();


	constexpr size_t bigbufsize = size_t(INT_MAX) * 2;
	auto bigbufSend = std::unique_ptr<char[]>(new char[bigbufsize]);
	auto bigbufReceive = std::unique_ptr<char[]>(new char[bigbufsize]);
	auto ptr = bigbufSend.get();
	for (size_t i = 0; i < bigbufsize; i++)
		ptr[i] = (char)i;

	asyncSend(s, bigbufSend.get(), bigbufsize, -1, [&](const Error& ec, size_t transfered)
	{
		CHECK_CZSPAS_EQUAL(Success, ec);
		CHECK_EQUAL(bigbufsize, transfered);
		done.notify();
	});

	asyncReceive(*server.socks[0].get(), bigbufReceive.get(), bigbufsize, -1, [&](const Error& ec, size_t transfered)
	{
		CHECK_CZSPAS_EQUAL(Success, ec);
		CHECK_EQUAL(bigbufsize, transfered);
		done.notify();
	});
	done.wait();
	done.wait();
	ptr = bigbufReceive.get();
	for (size_t i = 0; i < bigbufsize; i++)
	{
		CHECK_EQUAL(int(char(i)), int(ptr[i]));
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
