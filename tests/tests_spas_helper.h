#pragma once

#define TEST_LOG(fmt, ...) printf("TST: " fmt "\n", ##__VA_ARGS__)
#define CHECK_CZSPAS(ec) CHECK(ec.code == Error::Code::Success)

// Catch2 technically doesn't support using assertion macros from several thread, therefore for the thread that is not running
// the thing being tested, we a fatal error.
// This means the tests will stop when it detects something wrong, better than using Catch2's macros across several thread.
#define TEST_ASSERT(expr)                                                      \
	if (!(expr))                                                               \
	{                                                                          \
		CZSPAS_FATAL("ASSERT FAILED: (%s), %d:%s", #expr, __LINE__, __FILE__); \
	}



#define CZSPAS_DELETE_COPY_AND_MOVE(Class)     \
	Class(Class&&) = delete;                   \
	Class(const Class&) = delete;              \
	Class& operator=(Class&&) = delete;        \
	Class& operator=(const Class&&) = delete; 

using namespace cz;
using namespace cz::spas;

// The Data template type is just a dummy way to add state to a session if a unit test requires it
template<typename Data=int>
struct Session : std::enable_shared_from_this<Session<Data>>
{
	Session(Service& service) : sock(service) {}
	~Session()
	{
	}
	Socket sock;
	Data data;
};

template<typename Data=int>
struct AcceptorSession : std::enable_shared_from_this<AcceptorSession<Data>>
{
	AcceptorSession(Service& service, const char* bindIp, int port = -1, int backlog = 1) : acceptor(service)
	{
		if (port != -1)
		{
			auto ec = acceptor.listen(bindIp, port, backlog, false);
			CHECK_CZSPAS(ec);
		}
	}
	AcceptorSession(Service& service, int port = -1) : acceptor(service)
	{
		if (port != -1)
		{
			auto ec = acceptor.listen(port);
			CHECK_CZSPAS(ec);
		}
	}

	~AcceptorSession()
	{
	}
	Acceptor acceptor;
	Data data;
};

//! Helper class to run a Service in a separate thread.
struct ServiceThread
{
	CZSPAS_DELETE_COPY_AND_MOVE(ServiceThread);

	Service io;
	bool doStop = false;
	bool keepAlive = false;
	std::thread th;

	explicit ServiceThread(bool autoRun, bool keepAlive, bool doStop)
		: doStop(doStop)
		, keepAlive(keepAlive)
	{
		TEST_LOG("ServiceThread %p: Constructor", this);
		
		if (autoRun)
		{
			start();
		}
	}

	~ServiceThread()
	{
		TEST_LOG("ServiceThread %p: Destructor start", this);
		finish();
		TEST_LOG("ServiceThread %p: Destructor end", this);
	}

	void start()
	{
		CHECK(th.joinable() == false);
		th = std::thread([this]()
		{
			//std::this_thread::sleep_for(500ms);
			std::unique_ptr<Service::Work> work;
			if (keepAlive)
			{
				work = std::make_unique<Service::Work>(io);
			}

			io.run();
			TEST_LOG("ServiceThread %p: Finishing thread", this);
		});
	}

	void finish()
	{
		if (doStop)
		{
			io.stop();
		}

		if (th.joinable())
		{
			TEST_LOG("ServiceThread %p: Joining start", this);
			th.join();
			TEST_LOG("ServiceThread %p: Joining end", this);
		}
	}

};

template<
	typename H,
	typename = std::enable_if_t< std::is_same_v<void, typename std::result_of<H()>::type>> 
>
float measureTimeMs(H&& fn)
{
	auto start = std::chrono::high_resolution_clock::now();
	fn();
	float deltaMs = std::chrono::duration<float, std::milli>(std::chrono::high_resolution_clock::now() - start).count();
	return deltaMs;
}

template<
	typename H,
	typename = std::enable_if_t< !std::is_same_v<void, typename std::result_of<H()>::type>> 
>
std::pair<float, typename std::result_of<H()>::type> measureTimeMs(H&& fn)
{
	auto start = std::chrono::high_resolution_clock::now();
	auto res = fn();
	float deltaMs = std::chrono::duration<float, std::milli>(std::chrono::high_resolution_clock::now() - start).count();
	return {deltaMs, std::move(res)};
}

template<typename Duration>
float toMs(Duration d)
{
	return std::chrono::duration<float, std::milli>(d).count();
}
