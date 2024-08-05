#pragma once

#define TEST_LOG(fmt, ...) printf("TST: " fmt "\n", ##__VA_ARGS__)

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
	Service service;
	std::thread th;
	bool doStop = false;
	bool keepAlive = false;
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
				work = std::make_unique<Service::Work>(service);
			}

			service.run();
			TEST_LOG("ServiceThread %p: Finishing thread", this);
		});
	}

	void finish()
	{
		if (doStop)
		{
			service.stop();
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
