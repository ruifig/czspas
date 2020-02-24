/*
A simple echo server

The server waits for connections, and echoes back any data sent by the client.
This is very similar to what the equivalent Asio sample does:
	http://think-async.com/Asio/asio-1.10.6/src/examples/cpp11/echo/async_tcp_echo_server.cpp

*/

#include <crazygaze/spas/spas.h>

using namespace cz;
using namespace cz::spas;

class ServerSession : public std::enable_shared_from_this<ServerSession>
{
public:
	ServerSession(Service& service)
		: m_socket(service)
	{}

	~ServerSession()
	{
		auto addr = m_socket.getPeerAddr();
		printf("Finishing session with %s:%d\n", addr.first.c_str(), addr.second);
	}

	void start()
	{
		auto addr = m_socket.getPeerAddr();
		printf("Starting session with %s:%d\n", addr.first.c_str(), addr.second);
		do_read();
	}

private:

	void do_read()
	{
		auto self(shared_from_this());
		m_socket.asyncReceiveSome(m_data, sizeof(m_data), -1,
			[this, self](const Error& ec, size_t transfered)
		{
			if (!ec)
				do_write(transfered);
		});
	}

	void do_write(size_t transfered)
	{
		auto self(shared_from_this());
		asyncSend(m_socket, m_data, transfered, -1, [this, self](const Error& ec, size_t transfered)
		{
			if (!ec)
				do_read();
		});
	}

	Socket m_socket;
	char m_data[64];
	friend class Server;
};

class Server
{
public:
	Server(Service& service, int port)
		: m_acceptor(service)
	{
		auto ec = m_acceptor.listen(port);
		if (ec)
			throw std::runtime_error(ec.msg());
		do_accept();
	}

private:
	void do_accept()
	{
		auto session = std::make_shared<ServerSession>(m_acceptor.getService());
		m_acceptor.asyncAccept(session->m_socket, -1, [this, session](const Error& ec)
		{
			if (!ec)
				session->start();
			do_accept();
		});
	}

	Acceptor m_acceptor;
};

int do_main(int argc, char* argv[])
{
	printf("EchoServer sample\n");

	if (argc != 2)
	{
		fprintf(stderr, "Usage: EchoServer <port>\n");
		return EXIT_FAILURE;
	}

	Service service;
	Server server(service, std::stoi(argv[1]));

	service.run();

	return EXIT_SUCCESS;
}

int main(int argc, char* argv[])
{
	try
	{
		return do_main(argc, argv);
	}
	catch (std::exception& e)
	{
		fprintf(stderr, "Exception: %s\n", e.what());
		return EXIT_FAILURE;
	}
}

