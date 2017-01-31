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

	auto ft1 = std::async([&ac, &io]
	{
		UnitTest::Timer timer;
		timer.Start();
		Socket s(io);
		auto ec = ac.accept(s);
		CHECK_CZSPAS_EQUAL(Other, ec);
	});

	auto ft2 = std::async([&ac]
	{
		// Give it some time for the other thread to start the accept
		UnitTest::TimeHelpers::SleepMs(100);
		// Closing the socket on our own, to cause the accept to break
		::closesocket(ac.getHandle());
	});

	ft1.get();
	ft2.get();
}


TEST(Acceptor_tmp)
{
	Service io;
	Acceptor ac(io);
	auto ec = ac.listen(SERVER_PORT, 1);
	CHECK_CZSPAS(ec);

	auto ft = std::async([&io]
	{
		UnitTest::TimeHelpers::SleepMs(100);
		Socket s(io);
		auto ec = s.connect("127.0.0.1", SERVER_PORT);
		CHECK_CZSPAS(ec);
	});

	Socket s(io);
	ac.accept(s, 1000);
	ft.get();
}

}
