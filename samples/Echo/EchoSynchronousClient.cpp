/*
A simple echo client.

It connects to a server, sends the specified string, and waits for the server to send it back.

While for a server it makes more sense to use asynchronous functions, so we can handle several
clients, for a client sometimes its easier to just use synchronous functions to keep things simple.

#TODO : Change to use free functions send and receive
*/

#include <crazygaze/spas/spas.h>
#include <iostream>

using namespace cz;
using namespace cz::spas;

int main(int argc, char* argv[])
{
	try
	{
		printf("EchoSynchronousClient sample\n");
		if (argc != 3)
		{
			fprintf(stderr, "Usage: EchoClient <ip> <port>\n");
			return EXIT_FAILURE;
		}

		Service service;

		Socket s(service);
		auto ec = s.connect(argv[1], std::stoi(argv[2]));
		if (ec)
			throw std::runtime_error(std::string("Error connecting to host: ") + ec.msg());

		constexpr int maxLength = 1024;

		// Send message (including null terminator)
		std::cout << "Enter message: ";
		char out[maxLength];
		std::cin.getline(out, maxLength);
		auto msgLength = strlen(out) + 1;
		send(s, out, msgLength, -1, ec);

		// Receive message
		char in[maxLength];
		receive(s, in, msgLength, -1, ec);
		printf("Reply is: %s\n", in);

		return EXIT_SUCCESS;
	}
	catch (std::exception& e)
	{
		fprintf(stderr, "Exception: %s\n", e.what());
		return EXIT_FAILURE;
	}
}
