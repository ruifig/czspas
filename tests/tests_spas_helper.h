#pragma once

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
		if (autoRun)
			run();
	}

	~ServiceThread()
	{
		finish();
	}

	void run()
	{
		CHECK(th.joinable() == false);
		th = std::thread([this]()
		{
			//UnitTest::TimeHelpers::SleepMs(500);
			std::unique_ptr<Service::Work> work;
			if (keepAlive)
				work = std::make_unique<Service::Work>(service);
			service.run();
		});
	}

	void finish()
	{
		if (doStop)
			service.stop();
		if (th.joinable())
			th.join();
	}

};
