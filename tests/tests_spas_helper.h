#pragma once

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
	AcceptorSession(Service& service, int port = -1, int backlog = 1) : acceptor(service)
	{
		if (port != -1)
		{
			auto ec = acceptor.listen(port, backlog);
			CHECK_CZSPAS(ec);
		}
	}
	~AcceptorSession()
	{
	}
	Acceptor acceptor;
	Data data;
};

struct ServiceThread
{
	Service service;
	std::thread th;
	UnitTest::Timer timer;
	ServiceThread()
	{
		timer.Start();
		th = std::thread([this]()
		{
			service.run();
		});
	}

	~ServiceThread()
	{
		service.stop();
		th.join();
	}
};


