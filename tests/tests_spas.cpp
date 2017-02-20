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

SUITE(CZSPAS)
{

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
	CHECK_CZSPAS_EQUAL(Cancelled, ec);

	timer.Start();
	ec = ac.accept(s, 1050);
	CHECK_CLOSE(1050, timer.GetTimeInMs(), 20);
	CHECK_CZSPAS_EQUAL(Cancelled, ec);
}

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
		UnitTest::TimeHelpers::SleepMs(100);

		// Closing the socket on our own, to cause the accept to break
		// Initially I was calling spas::details::utils::closeSocket(ac.getHandle()), which works fine on Windows.
		// It does a shutdown with SD_BOTH on Windows, and SD_RDWR on Linux, but it seems on Linux, using a shutdown with
		// SD_RDWR doesn't cause the ::select used internally by Acceptor::accept to break. It hangs forever.
        // So, I need to do a manual shutdown with SHUT_RD
#if _WIN32
		spas::details::utils::closeSocket(ac.getHandle());
#else
		::shutdown(ac.getHandle(), SHUT_RD);
#endif
	});

	ft1.get();
	ft2.get();
}

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
	Acceptor ac(io);
	auto ec = ac.listen(SERVER_PORT, 1);
	CHECK_CZSPAS(ec);
	auto ft = std::async(std::launch::async, [&ac, &serverSide]
	{
		auto ec = ac.accept(serverSide, 1000);
		CHECK_CZSPAS(ec);
	});

	Socket s(io);
	Semaphore done;
	UnitTest::Timer timer;
	timer.Start();
	s.asyncConnect("127.0.0.1", SERVER_PORT, [&](const Error& ec)
	{
		if (ec)
		{
			auto t = timer.GetTimeInMs();
			printf("");
		}
		CHECK_CZSPAS(ec);
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
	s.asyncConnect("127.0.0.1", SERVER_PORT, [&](const Error& ec)
	{
		CHECK_CZSPAS_EQUAL(Cancelled, ec);
		CHECK_CLOSE(timeoutMs, timer.GetTimeInMs(), 20);
		io.stop(); // stop the service, to finish this test
		done.notify();
	}, timeoutMs);
	io.run();
	done.wait(); // To make sure the asyncConnect gets called
}

TEST(Dummy)
{
	{
		details::IODemux demux;
		UnitTest::TimeHelpers::SleepMs(1000);
	}
	printf("\n");
}


}
