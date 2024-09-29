/*
------------------------------------------------------------------------------
This source file is part of czspas (Small Portable Asynchronous Sockets)
https://github.com/ruifig/czspas

Copyright (c) 2017 Rui Figueira and czspas contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "spas.h"

namespace cz::spas::detail
{
	//////////////////////////////////////////////////////////////////////////
	// ErrorWrapper
	//////////////////////////////////////////////////////////////////////////
	class ErrorWrapper
	{
	public:
#if _WIN32
		static std::string getWin32ErrorMsg(DWORD err = ERROR_SUCCESS, const char* funcname = nullptr)
		{
			LPVOID lpMsgBuf;
			LPVOID lpDisplayBuf;
			if (err == ERROR_SUCCESS)
			{
				err = GetLastError();
			}

			FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				err,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(char*)&lpMsgBuf,
				0,
				NULL);

			CZSPAS_SCOPE_EXIT{ LocalFree(lpMsgBuf); };

			int funcnameLength = funcname ? (int)strlen(funcname) : 0;
			lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, (strlen((char*)lpMsgBuf) + funcnameLength + 50));
			if (lpDisplayBuf == nullptr)
			{
				return "";
			}
			CZSPAS_SCOPE_EXIT{ LocalFree(lpDisplayBuf); };

			StringCchPrintfA(
				(char*)lpDisplayBuf,
				LocalSize(lpDisplayBuf),
				"%s failed with error %d: %s",
				funcname ? funcname : "",
				err,
				(const char*)lpMsgBuf);

			std::string ret = (char*)lpDisplayBuf;

			// Remove the \r\n at the end
			while (ret.size() && ret.back() < ' ')
			{
				ret.pop_back();
			}

			return ret;
		}

		ErrorWrapper() { m_err = WSAGetLastError(); }
		explicit ErrorWrapper(int err) : m_err(err) {}
		std::string msg() const { return getWin32ErrorMsg(m_err); }
		bool isBlockError() const { return m_err == WSAEWOULDBLOCK; }
		bool isHostNotFoundError() const { return m_err == WSAHOST_NOT_FOUND; }
		bool isTryAgainError() const { return m_err == WSATRY_AGAIN; }
		int getCode() const { return m_err; };
#else
		ErrorWrapper() { m_err = errno; }
		explicit ErrorWrapper(int err) 
		{
			m_err = err == EAI_SYSTEM ? errno : err;
		}

		bool isBlockError() const { return m_err == EAGAIN || m_err == EWOULDBLOCK || m_err == EINPROGRESS; }
		bool isHostNotFoundError() const { return m_err == EAI_NONAME; }
		bool isTryAgainError() const { return m_err == EAI_AGAIN; ;}
		// #TODO Build custom error depending on the error number
		std::string msg() const { return strerror(m_err); }
		int getCode() const { return m_err; };
#endif

		Error getError() const { return Error(Error::Code::Other, msg()); }
	private:
		int m_err;
	};


	//////////////////////////////////////////////////////////////////////////
	// WSAInstance
	//////////////////////////////////////////////////////////////////////////

#if _WIN32
	WSAInstance::WSAInstance()
	{
		CZSPAS_INFO("WSAInstance %p: Constructor", this);
		WORD wVersionRequested = MAKEWORD(2, 2);
		WSADATA wsaData;
		int err = WSAStartup(wVersionRequested, &wsaData);
		if (err != 0)
		{
			CZSPAS_FATAL(ErrorWrapper().msg().c_str());
		}

		if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
		{
			WSACleanup();
			CZSPAS_FATAL("Could not find a usable version of Winsock.dll");
		}
	}

	WSAInstance::~WSAInstance()
	{
		CZSPAS_INFO("WSAInstance %p: Destructor", this);
		WSACleanup();
	}
#endif

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////

	// To work around the Windows vs Linux shenanigans with strncpy/strcpy/strlcpy, etc.
	template<unsigned int N>
	inline void copyStrToFixedBuffer(char (&dst)[N], const char* src)
	{
	#if _WIN32
		strncpy_s(dst, sizeof(dst), src, sizeof(dst)-1);
	#else
		strncpy(dst, src, sizeof(dst));
		dst[sizeof(dst)-1] = 0;
	#endif
	}

	void defaultLogOutput(bool fatal, const char* type, const char* fmt, ...)
	{
		char buf[512];
		copyStrToFixedBuffer(buf, type);
		va_list args;
		va_start(args, fmt);
		buf[512-1] = 0;
		vsnprintf(buf + strlen(buf), sizeof(buf) - strlen(buf) - 1, fmt, args);
		va_end(args);
		printf("%s\n",buf);
	}

	// Adapted from http://stackoverflow.com/questions/1543466/how-do-i-change-a-tcp-socket-to-be-non-blocking
	static void setBlocking(SocketHandle s, bool blocking)
	{
		CZSPAS_ASSERT(s != CZSPAS_INVALID_SOCKET);
#if _WIN32
		// 0: Blocking. !=0 : Non-blocking
		u_long mode = blocking ? 0 : 1;
		int res = ioctlsocket(s, FIONBIO, &mode);
		if (res != 0)
			CZSPAS_FATAL(ErrorWrapper().msg().c_str());
#else
		int flags = fcntl(s, F_GETFL, 0);
		if (flags <0)
			CZSPAS_FATAL(ErrorWrapper().msg().c_str());
		flags = blocking ? (flags&~O_NONBLOCK) : (flags|O_NONBLOCK);
		if (fcntl(s, F_SETFL, flags) != 0)
			CZSPAS_FATAL(ErrorWrapper().msg().c_str());
#endif
	}

	static void optimizeLoopback(SocketHandle s)
	{
#if _WIN32
		int optval = 1;
		DWORD NumberOfBytesReturned = 0;
		int status = WSAIoctl(
				s,
				SIO_LOOPBACK_FAST_PATH,
				&optval,
				sizeof(optval),
				NULL,
				0,
				&NumberOfBytesReturned,
				0,
				0);

		if (status==CZSPAS_SOCKET_ERROR)
		{
			ErrorWrapper err;
			if (err.getCode() == WSAEOPNOTSUPP)
			{
				// This system is not Windows Server 2012, and the call is not supported.
				// Do nothing
			}
			else 
			{
				CZSPAS_FATAL(err.msg().c_str());
			}
		}
#endif
	}

	static void closeSocket(SocketHandle& s, bool doshutdown=true)
	{
		if (s == CZSPAS_INVALID_SOCKET)
		{
			return;
		}

		int res;
#if _WIN32
		if (doshutdown)
		{
			::shutdown(s, SD_BOTH);
		}

		res = ::closesocket(s);
#else
		if (doshutdown)
		{
			::shutdown(s, SHUT_RDWR);
		}

		res = ::close(s);
#endif

		//
		// According to Unix and Windows documentation, it is possible for the close to fail
		// with EWOULDBLOCK.
		// If that happens, put the socket back to blocking mode and try again
		// Asio also does this (include\asio\detail\impl\socket_ops.ipp : close)
		if (res!=0 && ErrorWrapper().isBlockError())
		{
			detail::setBlocking(s, true);
#if _WIN32
			res = ::closesocket(s);
#else
			res = ::close(s);
#endif
			if (res!=0)
			{
				ErrorWrapper e;
				CZSPAS_ERROR("Socket close failed and it will leak the handle: '%s'", e.msg().c_str());
			}
		}

		s = CZSPAS_INVALID_SOCKET;
	}

	static void disableNagle(SocketHandle s)
	{
		int flag = 1;
		int result = setsockopt(
			s, /* socket affected */
			IPPROTO_TCP,     /* set option at TCP level */
			TCP_NODELAY,     /* name of option */
			(char *)&flag,   /* the cast is historical cruft */
			sizeof(flag));   /* length of option value */

		if (result != 0)
		{
			CZSPAS_FATAL(ErrorWrapper().msg().c_str());
		}
	}

	static void setReuseAddress(SocketHandle s)
	{
		int optval = 1;
		int res = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&optval, sizeof(optval));
		if (res != 0)
		{
			CZSPAS_FATAL(ErrorWrapper().msg().c_str());
		}
	}

	// Set the linger option, in seconds
	static void setLinger(SocketHandle s, bool enabled, u_short timeoutSeconds)
	{
		linger l;
		l.l_onoff = enabled ? 1 : 0;
		l.l_linger = timeoutSeconds;
		int res = setsockopt(s, SOL_SOCKET, SO_LINGER, (const char*)&l, sizeof(l));
		if (res != 0)
		{
			CZSPAS_FATAL(ErrorWrapper().msg().c_str());
		}
	}

	static Error getSocketError(SocketHandle s)
	{
		int result;
		socklen_t result_len = sizeof(result);
		if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&result, &result_len)<0)
		{
			return ErrorWrapper().getError();
		}
		else
		{
			if (result)
			{
				return ErrorWrapper(result).getError();
			}
			else
			{
				return Error();
			}
		}
	}

	static std::pair<std::string, int> addrToPair(sockaddr_in& addr)
	{
		std::pair<std::string, int> res;
		char str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(addr.sin_addr), str, INET_ADDRSTRLEN);
		res.first = str;
		res.second = ntohs(addr.sin_port);
		return res;
	}

	static std::pair<std::string, int> getLocalAddr(SocketHandle s)
	{
		sockaddr_in addr;
		socklen_t size = sizeof(addr);
		if (getsockname(s, (sockaddr*)&addr, &size) != CZSPAS_SOCKET_ERROR && size == sizeof(addr))
		{
			return addrToPair(addr);
		}
		else
		{
			CZSPAS_ERROR(ErrorWrapper().msg().c_str());
			return std::make_pair("", 0);
		}
	}

	static std::pair<std::string, int> getRemoteAddr(SocketHandle s)
	{
		sockaddr_in addr;
		socklen_t size = sizeof(addr);
		if (getpeername(s, (sockaddr*)&addr, &size) != CZSPAS_SOCKET_ERROR)
		{
			return addrToPair(addr);
		}
		else
		{
			return std::make_pair("0.0.0.0", 0);
		}
	}

	//! Creates a socket and puts it into listen mode
	//
	// \param bindIP
	//		What IP to bind to.
	// \param port
	//		What port to listen on. If 0, the OS will pick a port from the dynamic range
	// \param ec
	//		If an error occurs, this contains the error.
	// \param backlog
	//		Size of the connection backlog.
	//		Also, this is only an hint to the OS. It's not guaranteed.
	//
	static std::pair<Error, SocketHandle> createListenSocket(zstring_view bindIP, int port, int backlog, bool reuseAddr)
	{
		SocketHandle s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (s == CZSPAS_INVALID_SOCKET)
		{
			return std::make_pair(detail::ErrorWrapper().getError(), s);
		}

		if (reuseAddr)
		{
			detail::setReuseAddress(s);
		}

		sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(static_cast<uint16_t>(port));
		if (bindIP == "" || bindIP=="0.0.0.0")
		{
			addr.sin_addr.s_addr = htonl(INADDR_ANY);
		}
		else
		{
			inet_pton(AF_INET, bindIP, &(addr.sin_addr));
		}

		if (
			(::bind(s, (const sockaddr*)&addr, sizeof(addr)) == CZSPAS_SOCKET_ERROR) ||
			(::listen(s, backlog) == CZSPAS_SOCKET_ERROR)
			)
		{
			auto ec = detail::ErrorWrapper().getError();
			closeSocket(s);
			return std::make_pair(ec, CZSPAS_INVALID_SOCKET);
		}

		// Enable any loopback optimizations (in case this socket is used in a loopback)
		detail::optimizeLoopback(s);

		return std::make_pair(Error(), s);
	}

	static std::pair<Error, SocketHandle> createListenSocket(int port)
	{
		return createListenSocket("", port, SOMAXCONN, false);
	}

	//! Synchronous connect
	static std::pair<Error, SocketHandle> createConnectSocket(zstring_view ip, int port)
	{
		SocketHandle s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (s == CZSPAS_INVALID_SOCKET)
		{
			return std::make_pair(detail::ErrorWrapper().getError(), s);
		}

		// Enable any loopback optimizations (in case this socket is used in loopback)
		detail::optimizeLoopback(s);

		sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(static_cast<uint16_t>(port));
		inet_pton(AF_INET, ip, &(addr.sin_addr));
		if (::connect(s, (const sockaddr*)&addr, sizeof(addr)) == CZSPAS_SOCKET_ERROR)
		{
			auto ec = detail::ErrorWrapper().getError();
			closeSocket(s);
			return std::make_pair(ec, CZSPAS_INVALID_SOCKET);
		}

		detail::setBlocking(s, false);
		return std::make_pair(Error(), s);
	}

	static std::pair<bool, Error> doSelect(SocketHandle& sock, bool read, int timeoutMs)
	{
		CZSPAS_ASSERT(sock != CZSPAS_INVALID_SOCKET);

		timeval timeout{ 0,0 };
		if (timeoutMs != -1)
		{
			timeout.tv_sec = static_cast<long>((long)(timeoutMs) / 1000);
			timeout.tv_usec = static_cast<long>(((long)(timeoutMs) % 1000) * 1000);
		}

		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		auto res = ::select(
			(int)sock + 1,
			read ? &fds : NULL,
			read ? NULL : &fds,
			NULL,
			timeoutMs == -1 ? NULL : &timeout);

		if (res == 0) // Timeout
		{
			return std::make_pair(false, Error(Error::Code::Timeout));
		}
		else if (res == 1)
		{
			return std::make_pair(true, Error());
		}
		else if (res == CZSPAS_SOCKET_ERROR)
		{
			return std::make_pair(false, detail::ErrorWrapper().getError());
		}
		else
		{
			CZSPAS_ASSERT(0 && "Unexpected");
			return std::make_pair(false, Error(Error::Code::Other));
		}
	}

	static std::pair<Error, SocketHandle> accept(SocketHandle& acceptor, int timeoutMs = -1)
	{
		auto res = doSelect(acceptor, true, timeoutMs);

		if (res.second) // Return any error
		{
			return std::make_pair(res.second, CZSPAS_INVALID_SOCKET);
		}

		sockaddr_in addr;
		socklen_t size = sizeof(addr);
		SocketHandle s = ::accept(acceptor, (struct sockaddr*)&addr, &size);
		if (s == CZSPAS_INVALID_SOCKET)
		{
			return std::make_pair(detail::ErrorWrapper().getError(), s);
		}

		detail::setBlocking(s, false);

		return std::make_pair(Error(), s);
	}


	//////////////////////////////////////////////////////////////////////////
	// SocketHelper
	//////////////////////////////////////////////////////////////////////////

	SocketHelper::SocketHelper(Service& owner)
		: owner(owner)
	{
	}

	SocketHelper::~SocketHelper()
	{
		CZSPAS_ASSERT(pendingAccept.load() == 0);
		CZSPAS_ASSERT(pendingConnect.load() == 0);
		CZSPAS_ASSERT(pendingSend.load() == 0);
		CZSPAS_ASSERT(pendingReceive.load() == 0);
	}

	void SocketHelper::setLinger(bool enabled, unsigned short timeoutSeconds)
	{
		detail::setLinger(s, enabled, timeoutSeconds);
	}

	void SocketHelper::_forceClose(bool doshutdown)
	{
		detail::closeSocket(s, doshutdown);
	}

	void SocketHelper::resolveAddrs()
	{
		localAddr = detail::getLocalAddr(s);
		peerAddr = detail::getRemoteAddr(s);
	}

	cz::spas::SocketHandle SocketHelper::getHandle()
	{
		return s;
	}

	cz::spas::Service& SocketHelper::getService()
	{
		return owner;
	}

	const std::pair<std::string, int>& SocketHelper::getLocalAddr() const
	{
		return localAddr;
	}

	const std::pair<std::string, int>& SocketHelper::getPeerAddr() const
	{
		return peerAddr;
	}

	bool SocketHelper::isValid() const
	{
		return s != CZSPAS_INVALID_SOCKET;
	}

	//////////////////////////////////////////////////////////////////////////
	// Operation
	//////////////////////////////////////////////////////////////////////////

	Operation::Operation(std::atomic<int>* dbgCounter)
		: dbgCounter(dbgCounter)
	{
		if (dbgCounter)
		{
			++(*dbgCounter);
		}
	}

	Operation::~Operation()
	{
		// Derived classed must call setFinished where required
		assert(dbgCounter == nullptr);
	}

	void Operation::setFinished()
	{
		if (dbgCounter)
		{
			--(*dbgCounter);
			dbgCounter = nullptr;
		}
	}

	//////////////////////////////////////////////////////////////////////////
	// ResolveOperation
	//////////////////////////////////////////////////////////////////////////

	void ResolveOperation::callUserHandler()
	{
		userHandler(ec, ip);
	}

	//////////////////////////////////////////////////////////////////////////
	// PostOperation
	//////////////////////////////////////////////////////////////////////////


	void PostOperation::callUserHandler()
	{
		userHandler();
	}

	//////////////////////////////////////////////////////////////////////////
	// SocketOperation
	//////////////////////////////////////////////////////////////////////////

	SocketOperation::SocketOperation(SocketHelper& owner, std::atomic<int>* dbgCounter) : Operation(dbgCounter)
		, owner(owner)
	{
	}

	//////////////////////////////////////////////////////////////////////////
	// AcceptOperation
	//////////////////////////////////////////////////////////////////////////

	AcceptOperation::~AcceptOperation()
	{
		setFinished();
	}

	void AcceptOperation::exec(SocketHandle fd, bool hasPOLLHUP)
	{
		sockaddr_in addr;
		socklen_t size = sizeof(addr);
		sock.s = ::accept(fd, (struct sockaddr*)&addr, &size);
		if (sock.s == CZSPAS_INVALID_SOCKET)
		{
			ec = detail::ErrorWrapper().getError();
		}
		else
		{
			detail::setBlocking(sock.s, false);
			sock.resolveAddrs();
		}
	}

	void AcceptOperation::callUserHandler()
	{
		userHandler(ec);
	}

	//////////////////////////////////////////////////////////////////////////
	// ConnectOperation
	//////////////////////////////////////////////////////////////////////////

	ConnectOperation::~ConnectOperation()
	{
		setFinished();
	}

	void ConnectOperation::exec(SocketHandle fd, bool hasPOLLHUP)
	{
		CZSPAS_ASSERT(fd == owner.getHandle());
		ec = detail::getSocketError(fd);
		if (!ec)
		{
			owner.resolveAddrs();
		}
	}

	void ConnectOperation::callUserHandler()
	{
		userHandler(ec);
	}

	//////////////////////////////////////////////////////////////////////////
	// TransferOperation
	//////////////////////////////////////////////////////////////////////////

	TransferOperation::~TransferOperation()
	{
		setFinished();
	}

	void TransferOperation::callUserHandler()
	{
		userHandler(ec, transfered);
	}

	//////////////////////////////////////////////////////////////////////////
	// SendOperation
	//////////////////////////////////////////////////////////////////////////

	void SendOperation::exec(SocketHandle fd, bool hasPOLLHUP)
	{
		CZSPAS_ASSERT(fd == owner.getHandle());
		// The interface allows size_t, but the implementation only allows int
		int todo = bufSize > INT_MAX ? INT_MAX : static_cast<int>(bufSize);
		int flags = 0;
#if __linux__
		flags = MSG_NOSIGNAL;
#endif
		int done = ::send(fd, reinterpret_cast<const char*>(buf), todo, flags);
		if (done == CZSPAS_SOCKET_ERROR)
		{
			if (hasPOLLHUP)
			{
				ec = Error(Error::Code::ConnectionClosed);
			}
			else
			{
				detail::ErrorWrapper err;
				ec = err.getError();
				if (err.isBlockError()) // Blocking can't happen at this point, since we got the event saying we can perform this type of operation
				{
					CZSPAS_FATAL("Blocking not expected at this point.");
				}
			}
		}
		else
		{
			transfered = done;
		}
	}

	//////////////////////////////////////////////////////////////////////////
	// ReceiveOperation
	//////////////////////////////////////////////////////////////////////////


	void ReceiveOperation::exec(SocketHandle fd, bool hasPOLLHUP)
	{
		CZSPAS_ASSERT(fd == owner.getHandle());
		// The interface allows size_t, but the implementation only allows int
		int todo = bufSize > INT_MAX ? INT_MAX : static_cast<int>(bufSize);
		int flags = 0;
#if __linux__
		flags = MSG_NOSIGNAL;
#endif
		int done = ::recv(fd, reinterpret_cast<char*>(buf), todo, flags);
		if (done == CZSPAS_SOCKET_ERROR)
		{
			if (hasPOLLHUP)
			{
				ec = Error(Error::Code::ConnectionClosed);
			}
			else
			{
				detail::ErrorWrapper err;
				ec = err.getError();
				if (err.isBlockError()) // Blocking can't happen at this point, since we got the event saying we can perform this type of operation
				{
					CZSPAS_FATAL("Blocking not expected at this point.");
				}
			}
		}
		else if (done == 0) // A disconnect
		{
			// On Windows, we never get here, since WSAPoll doesn't work exactly the same way has poll, according to what I've seen with my tests
			// Example, while on a WSAPoll, when a peer disconnects, the following happens:
			//	- Windows:
			//		- WSAPoll reports an error (POLLHUP)
			//	- Linux:
			//		- poll reports ready to read (success), and then recv reads 0 (which means the peer disconnected)
			ec = Error(Error::Code::ConnectionClosed);
		}
		else
		{
			transfered = done;
		}
	}


	//////////////////////////////////////////////////////////////////////////
	// Reactor
	//////////////////////////////////////////////////////////////////////////

	Reactor::Reactor()
	{
		// Create a listening socket on a port picked by the OS (because we passed 0 as port)
		auto acceptor = createListenSocket("127.0.0.1", 0, 1, false);
		// If this fails, then the OS probably ran out of resources (e.g: Too many connections or too many connection 
		// on TIME_WAIT)
		CZSPAS_ASSERT(!acceptor.first);

		// NOTE: We can connect without doing the accept first
		{
			auto res = detail::createConnectSocket("127.0.0.1", detail::getLocalAddr(acceptor.second).second);
			// Same as above. If this fails, then the OS ran out of resources
			CZSPAS_ASSERT(!res.first);
			m_signalOut = res.second;
		}

		// Loop until we accept the right connection.
		// This drops any unwanted connections (if it happens some other application tries to connect to our acceptor port)
		while (m_signalIn == CZSPAS_INVALID_SOCKET)
		{
			auto res = detail::accept(acceptor.second);
			if (res.first) // If some error occurred, just try and accept another.
			{
				continue;
			}

			// A simple check to make sure it's the connection we expect.
			// From the acceptor perspective, the remote port of the incoming connection must be the local port of m_signalOut
			if (detail::getRemoteAddr(res.second).second == detail::getLocalAddr(m_signalOut).second)
			{
				m_signalIn = res.second;
			}
			else
			{
				detail::closeSocket(res.second, false);
			}
		}

		detail::closeSocket(acceptor.second);
	}

	Reactor::~Reactor()
	{
		// To avoid the TIME_WAIT, we do the following:
		// 1. Disable lingering on the client socket (m_signalOut)
		// 2. Close client socket
		// 3. Close server side socket (m_signalIn). This the other socket was the one initiating the shutdown,
		//    this one doesn't go into TIME_WAIT
		detail::setLinger(m_signalOut, true, 0);
		detail::closeSocket(m_signalOut, false);
		detail::closeSocket(m_signalIn, false);
	}

	void Reactor::readInterrupt()
	{
		char buf[64];
		bool done = false;
		while (!done)
		{
			if (recv(m_signalIn, buf, sizeof(buf), 0) == CZSPAS_SOCKET_ERROR)
			{
				detail::ErrorWrapper err;
				if (err.isBlockError()) // This is expected, and it means there is no more data to read
				{
					done = true;
				}
				else
				{
					CZSPAS_FATAL("Reactor %p: %s", this, err.msg().c_str());
				}
			}
		}
	}

	void Reactor::setFd(pollfd& fd, const SocketData& data, Reactor::EventType type, Timepoint& timeout)
	{
		auto&& o = data.ops[type];
		if (!o.op)
		{
			return;
		}

		fd.events |= (type == Reactor::EventType::Read) ? POLLRDNORM : POLLWRNORM;
		if (o.timeout < timeout)
		{
			timeout = o.timeout;
		}
	}

	bool Reactor::processEventsHelper(SocketHandle fd, OperationData& opdata, int ready, bool hasPOLLHUP, Timepoint now, std::queue<std::unique_ptr<Operation>>& dst)
	{
		if (!opdata.op)
		{
			return true;
		}

		if (ready)
		{
			opdata.op->exec(fd, hasPOLLHUP);
			dst.push(std::move(opdata.op));
			return true;
		}
		else if (opdata.timeout < now)
		{
			opdata.op->ec = Error(Error::Code::Timeout);
			dst.push(std::move(opdata.op));
			return true;
		}
		else
		{
			return false;
		}
	}

	void Reactor::processEvents(std::queue<std::unique_ptr<Operation>>& dst)
	{
		auto now = std::chrono::high_resolution_clock::now();
		for (auto fdit = m_fds.begin() + 1; fdit != m_fds.end(); ++fdit)
		{
			auto&& fd = *fdit;
			auto it = m_sockData.find(fd.fd);
			if (it == m_sockData.end())
			{
				continue; // Socket data not present anymore (E.g: Operations were aborted while in the poll function)
			}

			// We can have POLLHUP but still have POLLRDNORM (Which means it disconnected, but we can still read some more data).
			// So to be safe, whenever POLLRDNORM or POLLWRNORM is set, we ignore the errors
			if (fd.revents & (POLLERR | POLLHUP | POLLNVAL) &&
				((fd.revents & (POLLRDNORM | POLLWRNORM)) == 0))
			{
				it->second.cancel((fd.revents & POLLHUP) ? Error::Code::ConnectionClosed : Error::Code::InvalidSocket, dst);
				m_sockData.erase(it);
			}
			else
			{
				bool hasPOLLHUP = (fd.revents & POLLHUP) != 0;
				bool empty = processEventsHelper(it->first, it->second.ops[EventType::Read],
					fd.revents & POLLRDNORM, hasPOLLHUP, now, dst);
				empty = processEventsHelper(it->first, it->second.ops[EventType::Write],
					fd.revents & POLLWRNORM, hasPOLLHUP, now, dst) && empty;
				if (empty)
				{
					m_sockData.erase(it);
				}
			}
		}
	}

	void Reactor::interrupt()
	{
		char buf = 0;
		int flags = 0;
#if __linux__
		flags = MSG_NOSIGNAL;
#endif
		if (::send(m_signalOut, &buf, 1, flags) != 1)
		{
			CZSPAS_FATAL("Reactor %p: %s", this, detail::ErrorWrapper().msg().c_str());
		}
	}

	void Reactor::addOperation(SocketHandle fd, EventType type, std::unique_ptr<SocketOperation> op, int timeoutMs)
	{
		std::unique_lock<std::mutex> lk(m_mtx);
		auto&& o = m_sockData[fd].ops[type];
		o.op = std::move(op);
		o.timeout = timeoutMs == -1 ? Timepoint::max()
			: std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(timeoutMs);
		interrupt();
	}

	void Reactor::cancel(SocketHandle fd, std::queue<std::unique_ptr<Operation>>& dst)
	{
		std::unique_lock<std::mutex> lk(m_mtx);
		auto it = m_sockData.find(fd);
		if (it == m_sockData.end())
		{
			return; // No operations for this socket found
		}
		it->second.cancel(Error::Code::Aborted, dst);
		m_sockData.erase(it);
		interrupt();
	}

	void Reactor::runOnce(std::queue<std::unique_ptr<Operation>>& dst)
	{
		std::unique_lock<std::mutex> lk(m_mtx);
		m_fds.clear();
		m_fds.push_back({ m_signalIn, POLLRDNORM, 0 }); // Reserve for the interrupt
		auto timeoutPoint = Timepoint::max();
		for (auto&& p : m_sockData)
		{
			m_fds.push_back({ p.first, 0, 0 });
			setFd(m_fds.back(), p.second, EventType::Read, timeoutPoint);
			setFd(m_fds.back(), p.second, EventType::Write, timeoutPoint);
			CZSPAS_ASSERT(m_fds.back().events != 0);
		}

		lk.unlock();

		int timeoutMs = -1;
		if (timeoutPoint != Timepoint::max())
		{
			timeoutMs = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(timeoutPoint - std::chrono::high_resolution_clock::now()).count());
			if (timeoutMs < 0)
			{
				timeoutMs = 0;
			}
		}

#if _WIN32
		auto res = WSAPoll(&m_fds.front(), static_cast<unsigned long>(m_fds.size()), timeoutMs);
#else
		auto res = poll(&m_fds.front(), static_cast<unsigned long>(m_fds.size()), timeoutMs);
#endif

		lk.lock();

		if (m_fds[0].revents & POLLRDNORM)
		{
			readInterrupt();
		}

		if (res == CZSPAS_SOCKET_ERROR)
		{
			CZSPAS_FATAL("Reactor %p: %s", this, detail::ErrorWrapper().msg().c_str());
		}
		else
		{
			CZSPAS_ASSERT(res >= 0);
			processEvents(dst);
		}
	}

	//////////////////////////////////////////////////////////////////////////
	// Reactor::OperationData
	//////////////////////////////////////////////////////////////////////////

	void Reactor::OperationData::cancel(Error::Code code, std::queue<std::unique_ptr<Operation>>& dst)
	{
		if (op)
		{
			op->ec = Error(code);
			dst.push(std::move(op));
		}
	}

	//////////////////////////////////////////////////////////////////////////
	// Reactor::SocketData
	//////////////////////////////////////////////////////////////////////////

	void Reactor::SocketData::cancel(Error::Code code, std::queue<std::unique_ptr<Operation>>& dst)
	{
		for (auto&& op : ops)
		{
			op.cancel(code, dst);
		}
	}

} // cz::spas::detail


namespace cz::spas
{


//////////////////////////////////////////////////////////////////////////
// Error
//////////////////////////////////////////////////////////////////////////
Error::Error(Code c)
	: code(c)
{
}

Error::Error(Code c, std::string_view msg)
	: code(c)
{
	setMsg(msg);
}

const char* Error::msg() const
{
	if (optionalMsg)
	{
		return optionalMsg->c_str();
	}

	switch (code)
	{
	case Code::Success: return "Success";
	case Code::Aborted: return "Aborted";
	case Code::Timeout: return "Timeout";
	case Code::ConnectionClosed: return "ConnectionClosed";
	case Code::InvalidSocket: return "InvalidSocket";
	case Code::HostNotFound: return "HostNotFound";
	case Code::Other: return "Other";
	default: return "Unknown";
	}
}

void Error::setMsg(std::string_view msg)
{
	// Always create a new one, since it might be shared by other instances
	optionalMsg = std::make_shared<std::string>(msg);
}

//////////////////////////////////////////////////////////////////////////
// Service
//////////////////////////////////////////////////////////////////////////

Service::Service()
{
	CZSPAS_INFO("Service %p: Constructor", this);
}

Service::~Service()
{
	CZSPAS_INFO("Service %p: Destructor", this);

	// Making sure all Operation objects are destroyed before Sockets, so we don't get the "pending" operations
	// asserts while destroying sockets.
	m_reactor.deleteOps();
}

size_t Service::run()
{
	if (m_outstandingWork == 0)
	{
		stop();
		return 0;
	}

	// NOTE: At first, I was resetting m_stopped to false here, but that is problematic:
	// E.g:
	// - One thread is created to call run
	// - Another thread calls stop() before the first thread has a chance to call run().
	// - The stop would be ignored (since we would be setting m_stopped to true here.
	size_t done = 0;

	while (!m_stopped)
	{
		{
			std::lock_guard<std::mutex> lk(m_mtx);
			// If an exception is thrown from a user handler, m_tmpready might still have items to execute. So
			// we do:
			// - If m_tmpready is empty, and we can do a swap since its faster
			// - If m_tmpready is not empty, append the m_ready contents
			if (m_tmpready.size() == 0)
			{
				std::swap(m_tmpready, m_ready);
			}
			else
			{
				while (m_ready.size())
				{
					m_tmpready.push(std::move(m_ready.front()));
					m_ready.pop();
				}
			}
		}

		// NOTE: We need to run ready handlers before and after checking the reactor.
		// If for example we only run ready handlers after the reactor.runOnce, then the service might get stuck
		// even if it has handlers to execute. Example of such case:
		// - Thread A calls Service::run, and blocks on the reactor, waiting for work
		// - Thread B calls (e.g) Acceptor::asyncAccept
		// - Thread B waits X seconds, so that thread A has time to process anything and get again blocked on the reactor
		// - Thread B calls Acceptor::cancel . This adds the aborted handler to m_ready
		// - Thread A will gets unblocked, and does
		//		- runReadyHandlers(m_tmpready); // Nothing done, since the only m_ready has handlers
		//		- loop and do std::swap(m_tmpread, m_ready) 
		//		- next m_reactor.runOnce will block forever, even though we have handlers in m_tmpready
		//
		done += runReadyHandlers(m_tmpready);
		m_reactor.runOnce(m_tmpready);
		done += runReadyHandlers(m_tmpready);
	}

	return done;
}

size_t Service::runReadyHandlers(std::queue<std::unique_ptr<detail::Operation>>& q)
{
	size_t done = 0;
	while (q.size())
	{
		done++;
		std::unique_ptr<detail::Operation> op = std::move(q.front());
		q.pop();
		// Make sure we consider this item as finished even if an exception is thrown from the user handler
		CZSPAS_SCOPE_EXIT{ workFinished(); };
		op->setFinished();
		op->callUserHandler();
	}
	return done;
}

void Service::stop()
{
	m_stopped = true;
	m_reactor.interrupt();
}

bool Service::isStopped() const
{
	return m_stopped.load();
}

void Service::reset()
{
	m_stopped = false;
}

void Service::workStarted()
{
	CZSPAS_INFO("Service %p: workStarted", this);
	++m_outstandingWork;
	CZSPAS_INFO("          : workStarted %d", m_outstandingWork.load());
}

void Service::workFinished()
{
	CZSPAS_INFO("Service %p: workFinished", this);
	auto n = --m_outstandingWork;
	CZSPAS_INFO("          : workFinished %d", n);
	CZSPAS_ASSERT(n >= 0);
	if (n == 0)
	{
		stop();
	}
}

void Service::cancel(SocketHandle fd)
{
	std::lock_guard<std::mutex> lk(m_mtx);
	m_reactor.cancel(fd, m_ready);
}

void Service::post(std::unique_ptr<detail::Operation> op)
{
	std::lock_guard<std::mutex> lk(m_mtx);
	workStarted();
	m_ready.push(std::move(op));
	// Awaken the reactor
	m_reactor.interrupt();
}

void Service::addReactorOperation(SocketHandle fd, detail::Reactor::EventType type, std::unique_ptr<detail::SocketOperation> op, int timeoutMs)
{
	workStarted();
	m_reactor.addOperation(fd, type, std::move(op), timeoutMs);
}

//////////////////////////////////////////////////////////////////////////
// Socket
//////////////////////////////////////////////////////////////////////////

Socket::Socket(Service& service) : m_base(service)
{

}

Socket::~Socket()
{
	detail::closeSocket(m_base.s);
}

Error Socket::connect(zstring_view ip, int port)
{
	CZSPAS_ASSERT(!m_base.isValid());

	CZSPAS_INFO("Socket %p: Connect(%s,%d)", this, ip.c_str(), port);
	auto res = detail::createConnectSocket(ip, port);
	if (res.first)
	{
		CZSPAS_ERROR("Socket %p: %s", this, res.first.msg());
		return res.first;
	}
	m_base.s = res.second;
	m_base.resolveAddrs();
	CZSPAS_INFO("Socket %p: Connected to %s:%d", this, m_base.peerAddr.first.c_str(), m_base.peerAddr.second);
	return Error();
}

void Socket::asyncConnect(zstring_view ip, int port, int timeoutMs, ConnectHandler h)
{
	CZSPAS_ASSERT(!m_base.isValid());
	CZSPAS_ASSERT(m_base.pendingConnect.load()==0 && "There is already a pending connect operation");
	CZSPAS_INFO("Socket %p: asyncConnect(%s,%d, %d, H)", this, ip.c_str(), port, timeoutMs);

	auto op = std::make_unique<detail::ConnectOperation>(m_base, std::move(h));

	m_base.s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (m_base.s == CZSPAS_INVALID_SOCKET)
	{
		// #RVF : Add test for entering this if block
		op->ec = detail::ErrorWrapper().getError();
		CZSPAS_ERROR("Socket %p: %s", this, op->ec.msg());
		getService().post(std::move(op));
		return;
	}

	// Enable any loopback optimizations (in case this socket is used in loopback)
	detail::optimizeLoopback(m_base.s);
	// Set to non-blocking, so we can do an asynchronous connect
	detail::setBlocking(m_base.s, false);

	sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(static_cast<uint16_t>(port));
	inet_pton(AF_INET, ip, &(addr.sin_addr));

	if (::connect(m_base.s, (const sockaddr*)&addr, sizeof(addr)) == CZSPAS_SOCKET_ERROR)
	{
		detail::ErrorWrapper err;
		if (err.isBlockError())
		{
			// Normal behaviour.
			// A asynchronous connect is done when we receive a write event on the socket
			getService().addReactorOperation(m_base.s, detail::Reactor::EventType::Write, std::move(op), timeoutMs);
		}
		else
		{
			// Any other error is a real error, so queue the handler for execution
			//detail::closeSocket(m_s);
			op->ec = err.getError();
			getService().post(std::move(op));
		}
	}
	else
	{
		// It may happen that the connect succeeds right away ?
		// If that happens, we can still wait for the reactor to detect the "ready to write" event.
		getService().addReactorOperation(m_base.s, detail::Reactor::EventType::Write, std::move(op), timeoutMs);
	}
}

size_t Socket::sendSome(const uint8_t* buf, size_t len, int timeoutMs, Error& ec)
{
	CZSPAS_ASSERT(len > 0);
	auto res = detail::doSelect(m_base.s, false, timeoutMs);
	if (res.second)
	{
		ec = res.second;
		return 0;
	}

	// The interface allows size_t, but the implementation only allows int
	int todo = len > INT_MAX ? INT_MAX : static_cast<int>(len);
	int flags = 0;
#if __linux__
	flags = MSG_NOSIGNAL;
#endif
	int done = ::send(m_base.s, reinterpret_cast<const char*>(buf), todo, flags);
	// I believe no errors should occur at this point, since the select told us the socket was ready, but doesn't
	// hurt to handle it.
	if (done == CZSPAS_SOCKET_ERROR)
	{
		ec = detail::ErrorWrapper().getError();
		return 0;
	}
	else
	{
		ec = Error();
		return done;
	}
}

size_t Socket::receiveSome(uint8_t* buf, size_t len, int timeoutMs, Error& ec)
{
	CZSPAS_ASSERT(len > 0);
	auto res = detail::doSelect(m_base.s, true, timeoutMs);
	if (res.second)
	{
		ec = res.second;
		return 0;
	}

	// The interface allows size_t, but the implementation only allows int
	int todo = len > INT_MAX ? INT_MAX : static_cast<int>(len);
	int flags = 0;
#if __linux__
	flags = MSG_NOSIGNAL;
#endif
	int done = ::recv(m_base.s, reinterpret_cast<char*>(buf), todo, flags);
	// I believe no errors should occur at this point, since the select told us the socket was ready, but doesn't
	// hurt to handle it.
	if (done == CZSPAS_SOCKET_ERROR)
	{
		ec = detail::ErrorWrapper().getError();
		return 0;
	}
	else if (done == 0)
	{
		// As per the ::recv documentation, 0 can be returned in two situations:
		// 1. A stream socket peer has performed a orderly shutdown.
		// 2. The requested number of bytes was 0
		ec = Error( todo==0 ? Error::Code::Success : Error::Code::ConnectionClosed);
		return 0;
	}
	else
	{
		ec = Error();
		return done;
	}
}

void Socket::cancel()
{
	if (m_base.isValid())
	{
		getService().cancel(m_base.s);
	}
}

void Socket::close()
{
	cancel();
	if (m_base.isValid())
	{
		detail::closeSocket(m_base.s, false);
	}
}

cz::spas::Service& Socket::getService()
{
	return m_base.getService();
}

void Socket::setLinger(bool enabled, unsigned short timeoutSeconds)
{
	m_base.setLinger(enabled, timeoutSeconds);
}

const std::pair<std::string, int>& Socket::getLocalAddr() const
{
	return m_base.getLocalAddr();
}

const std::pair<std::string, int>& Socket::getPeerAddr() const
{
	return m_base.getPeerAddr();
}

cz::spas::SocketHandle Socket::getHandle()
{
	return m_base.getHandle();
}

void Socket::_forceClose(bool doshutdown)
{
	m_base._forceClose(doshutdown);
}

//////////////////////////////////////////////////////////////////////////
// Acceptor
//////////////////////////////////////////////////////////////////////////


Acceptor::Acceptor(Service& service)
	: m_base(service)
{
}

Acceptor::~Acceptor()
{
	// Close the socket without calling shutdown, and setting linger to 0, so it doesn't linger around and we can
	// run another server right after
	// Not sure this is necessary for listening sockets.
	if (m_base.s != CZSPAS_INVALID_SOCKET)
	{
		detail::setLinger(m_base.s, true, 0);
	}

	detail::closeSocket(m_base.s, false);
}

Error Acceptor::listen(zstring_view bindIP, int port, int backlog, bool reuseAddr)
{
	CZSPAS_ASSERT(!m_base.isValid());
	CZSPAS_INFO("Acceptor %p: listen(%s, %d, %d)", this, bindIP.c_str(), port, backlog);
	
	std::pair<Error, SocketHandle> res = detail::createListenSocket(bindIP, port, backlog, reuseAddr);
	if (res.first)
	{
		CZSPAS_ERROR("Acceptor %p: %s", this, res.first.msg());
		return res.first;
	}
	m_base.s = res.second;

	m_base.resolveAddrs();

	// No error
	return Error();
}

Error Acceptor::listen(int port)
{
	bool reuseAddr = false;
#if __linux__
	reuseAddr = true;
#endif
	return listen("", port, SOMAXCONN, reuseAddr);
}

Error Acceptor::accept(Socket& sock, int timeoutMs /*= -1*/)
{
	CZSPAS_ASSERT(m_base.isValid());
	CZSPAS_ASSERT(!sock.m_base.isValid());

	std::pair<Error, SocketHandle> res = detail::accept(m_base.s, timeoutMs);
	if (res.first)
	{
		CZSPAS_ERROR("Acceptor %p: %s", this, res.first.msg());
		return res.first;
	}
	sock.m_base.s = res.second;
	sock.m_base.resolveAddrs();
	CZSPAS_INFO("Acceptor %p: Socket %p connected to %s:%d", this, &sock, sock.m_base.peerAddr.first.c_str(),
		sock.m_base.peerAddr.second);

	// No error
	return Error();
}

void Acceptor::cancel()
{
	if (m_base.isValid())
	{
		m_base.getService().cancel(m_base.s);
	}
}

void Acceptor::close()
{
	cancel();
	if (m_base.isValid())
	{
		detail::closeSocket(m_base.s, false);
	}
}

cz::spas::Service& Acceptor::getService()
{
	return m_base.getService();
}

void Acceptor::setLinger(bool enabled, unsigned short timeout)
{
	m_base.setLinger(enabled, timeout);
}

const std::pair<std::string, int>& Acceptor::getLocalAddr() const
{
	return m_base.getLocalAddr();
}

cz::spas::SocketHandle Acceptor::getHandle()
{
	return m_base.getHandle();
}

void Acceptor::_forceClose(bool doshutdown)
{
	m_base._forceClose(doshutdown);
}

//////////////////////////////////////////////////////////////////////////
// Free functions
//////////////////////////////////////////////////////////////////////////

namespace detail
{
	struct syncImpl
	{
		static size_t send(Socket& sock, const uint8_t* buf, size_t len, int timeoutMs, Error& ec)
		{
			size_t transfered = 0;
			while (!ec && transfered < len)
			{
				transfered += sock.sendSome(buf + transfered, len - transfered, timeoutMs, ec);
			}
			return transfered;
		}

		static size_t receive(Socket& sock, uint8_t* buf, size_t len, int timeoutMs, Error& ec)
		{
			size_t transfered = 0;
			while (!ec && transfered < len)
			{
				transfered += sock.receiveSome(buf + transfered, len - transfered, timeoutMs, ec);
			}
			return transfered;
		}
	};
}
 
size_t send(Socket& sock, const uint8_t* buf, size_t len, int timeoutMs, Error& ec)
{
	CZSPAS_ASSERT(len > 0);
	return detail::syncImpl::send(sock, buf, len, timeoutMs, ec);
}

size_t send(Socket& sock, const uint8_t* buf, size_t len, Error& ec)
{
	CZSPAS_ASSERT(len > 0);
	return detail::syncImpl::send(sock, buf, len, -1, ec);
}

size_t receive(Socket& sock, uint8_t* buf, size_t len, int timeoutMs, Error& ec)
{
	CZSPAS_ASSERT(len > 0);
	return detail::syncImpl::receive(sock, buf, len, timeoutMs, ec);
}

size_t receive(Socket& sock, uint8_t* buf, size_t len, Error& ec)
{
	CZSPAS_ASSERT(len > 0);
	return detail::syncImpl::receive(sock, buf, len, -1, ec);
}


//////////////////////////////////////////////////////////////////////////
// isPrivateIP
//////////////////////////////////////////////////////////////////////////

namespace detail
{

	uint32_t byteSwap (uint32_t v)
	{
		uint8_t a = v >> 24;
		uint8_t b = (v >> 16) & 0xFF;
		uint8_t c = (v >> 8 ) & 0xFF;
		uint8_t d = v & 0xFF;
		return (d << 24) | (c << 16) | (b <<8) | a;
	}


	/**
	 * Given a "xxx.xxx.xxx.xxx" string (an IP), it returns the numeric representation
	 */
	std::optional<IPAddress> strToAddr(zstring_view str)
	{
		// Enough bytes to store 255.255.255.255 + null
		constexpr int maxLen = 4*3 + 3 + 1;
		if (str.size() >= maxLen)
		{
			return std::nullopt;
		}

		char buf[maxLen];
		memcpy(buf, str.data(), str.size());
		buf[str.size()] = 0;
		
		unsigned int a,b,c,d;
		char extra;

		// It's not sufficient to check if the numbers were parsed.
		// E.g: 192.168.0.0.0 is an invalid ip (the extra 0). If we only checked if the numbers were parsed, we wouldn't detect
		// the error.
		// Therefore, we put an extra %c at the end. If that is parsed, it means there string has extra stuff at the end and
		// should be considered invalid
		if (sscanf(buf, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4)
		{
			return std::nullopt;
		}

		if ((a > 255) || (b > 255) || (c > 255) || (d > 255))
		{
			return std::nullopt;
		}

		IPAddress addr;
		addr.o.o1 = static_cast<uint8_t>(a);
		addr.o.o2 = static_cast<uint8_t>(b);
		addr.o.o3 = static_cast<uint8_t>(c);
		addr.o.o4 = static_cast<uint8_t>(d);
		return addr;
	}

	std::string addrToStr(const IPAddress& addr)
	{
		return
			std::to_string(addr.o.o1) + "." +
			std::to_string(addr.o.o2) + "." +
			std::to_string(addr.o.o3) + "." +
			std::to_string(addr.o.o4);
	}

	/**
	 * Given a string with a CIDR (i.e 192.168.0.0/16), it will return two uint32_t with corresponding to the network and mask
	 */
	std::optional<std::pair<IPAddress, IPAddress>> cidrStrToAddrs(zstring_view cidr)
	{
		// Enough bytes to store 255.255.255.255/XX + null
		constexpr int maxLen = 4*3 + 3 + 3 + 1;
		if (cidr.size() >= maxLen)
		{
			return std::nullopt;
		}

		char buf[maxLen];
		memcpy(buf, cidr.data(), cidr.size());
		buf[cidr.size()] = 0;
		
		// It's not sufficient to check if the numbers were parsed.
		// E.g: 192.168.0.0/24 is an invalid ip (the extra 0). If we only checked if the numbers were parsed, we wouldn't detect
		// the error.
		// Therefore, we put an extra %c at the end. If that is parsed, it means there string has extra stuff at the end and
		// should be considered invalid
		unsigned int a,b,c,d, bits;
		char extra;
		if (sscanf(buf, "%u.%u.%u.%u/%u%c", &a, &b, &c, &d, &bits, &extra) != 5)
		{
			return std::nullopt;
		}

		if ((a > 255) || (b > 255) || (c > 255) || (d > 255) || (bits > 32))
		{
			return std::nullopt;
		}
		else
		{
			IPAddress network;
			network.o.o1 = a;
			network.o.o2 = b;
			network.o.o3 = c;
			network.o.o4 = d;

			uint64_t maskVal = (((uint64_t)1 << bits) - 1) << (32 - bits);
			IPAddress mask;
			mask.all = byteSwap(static_cast<uint32_t>(maskVal));
			return std::pair<IPAddress, IPAddress>(network, mask);
		}
	}

	bool isIPInRange(IPAddress ip_, IPAddress network_, IPAddress mask_)
	{
		uint32_t ip = byteSwap(ip_.all);
		uint32_t network = byteSwap(network_.all);
		uint32_t mask = byteSwap(mask_.all);

		uint32_t net_lower = network & mask;
		uint32_t net_upper = net_lower | (~mask);
		if (ip >= net_lower && ip <= net_upper)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	bool isIPInRange(uint32_t ip, uint32_t network, uint32_t mask)
	{
		uint32_t net_lower = network & mask;
		uint32_t net_upper = net_lower | (~mask);
		if (ip >= net_lower && ip <= net_upper)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

} // namespace details

std::optional<bool> isIPInRange(zstring_view ip, zstring_view network, zstring_view mask)
{
	std::optional<detail::IPAddress> ip_addr = detail::strToAddr(ip);
	std::optional<detail::IPAddress> network_addr = detail::strToAddr(network);
	std::optional<detail::IPAddress> mask_addr = detail::strToAddr(mask);

	// Check if all input parameters are valid ip addresses
	if (!ip_addr.has_value() || !network_addr.has_value() || !mask_addr.has_value())
	{
		return std::nullopt;
	}

	return detail::isIPInRange(*ip_addr, *network_addr, *mask_addr);
}

std::optional<bool> isIPInRange(zstring_view ip, zstring_view cidr)
{
	std::optional<detail::IPAddress> ip_addr = detail::strToAddr(ip);
	std::optional<std::pair<detail::IPAddress, detail::IPAddress>> networkAndMask = detail::cidrStrToAddrs(cidr);
	if (!ip_addr.has_value() || !networkAndMask.has_value())
	{
		return std::nullopt;
	}

	return detail::isIPInRange(*ip_addr, networkAndMask->first, networkAndMask->second);
}

// Implement based on https://softwareengineering.stackexchange.com/questions/384960/is-my-algorithm-for-determining-whether-a-ipv4-is-public-or-private-correct
//#error Implement isPrivateIP
std::optional<bool> isPrivateIP(zstring_view ip)
{
	std::optional<detail::IPAddress> addr = detail::strToAddr(ip);
	if (!addr.has_value())
	{
		return std::nullopt;
	}

	// Class A (10.0.0.0 to 10.255.255.255)
	if (addr->o.o1 == 10)
	{
		return true;
	}
	// Class B (172.16.0.0 to 172.31.255.255)
	else if (addr->o.o1 == 172 && addr->o.o2 >= 16 && addr->o.o2 <= 31)
	{
		return true;
	}
	// Class C (192.168.0.0 to 192.168.255.255)
	else if (addr->o.o1 == 192 && addr->o.o2 == 168)
	{
		return true;
	}

	return false;
}



//////////////////////////////////////////////////////////////////////////
// getAdaptersAddresses
//////////////////////////////////////////////////////////////////////////
#if _WIN32

// Enable disable full logging for getAdaptersAddress
#if 1
	#define getAdaptersAddressesLog printf
#else
	#define getAdaptersAddressesLog(...) ((void)0)
#endif

namespace 
{
template<typename T>
static std::vector<NetworkAdapterInfo::Address> walkAddresses(T pFirstAddr, const char* addrType, bool includeIPV6)
{
	// To silence the compiler warning about unused parameter when logging is disabled
	addrType = addrType;

	std::vector<NetworkAdapterInfo::Address> res;
	char buff[100];
	DWORD bufflen = 100;

	std::string log;

	auto pAddr = pFirstAddr;
	if (pAddr != NULL)
	{
		for (int i = 0; pAddr != NULL; i++)
		{
			NetworkAdapterInfo::Address addr;
			if (pAddr->Address.lpSockaddr->sa_family == AF_INET)
			{
				sockaddr_in* sa_in = (sockaddr_in*)pAddr->Address.lpSockaddr;
				addr.isIPV6 = false;
				addr.ipv4 = sa_in->sin_addr;
				addr.str = inet_ntop(AF_INET, &(sa_in->sin_addr), buff, bufflen);
				res.push_back(addr);
				log += std::string("\t\tIPV4:") + addr.str + "\n";
			}
			else if (pAddr->Address.lpSockaddr->sa_family == AF_INET6)
			{
				sockaddr_in6* sa_in6 = (sockaddr_in6*)pAddr->Address.lpSockaddr;
				if (includeIPV6)
				{
					addr.isIPV6 = true;
					addr.ipv6 = sa_in6->sin6_addr;
					addr.str = inet_ntop(AF_INET6, &(sa_in6->sin6_addr), buff, bufflen);
					res.push_back(addr);
				}
				log += std::string("\t\tIPV6:") + addr.str + "\n";
			}
			else
			{
				log += "\t\tUNSPEC\n";
			}
			pAddr = pAddr->Next;
		}
	}

	getAdaptersAddressesLog("\tNumber of %s Addresses: %d\n", addrType, (int)res.size());
	if (log.size())
		getAdaptersAddressesLog(log.c_str());

	return res;
}

}

std::vector<NetworkAdapterInfo> getAdaptersAddresses(bool onlyStatusUp, bool includeIPV6)
{
	std::vector<NetworkAdapterInfo> res;

	// Declare and initialize variables
	DWORD dwRetVal = 0;

	unsigned int i = 0;

	// Set the flags to pass to GetAdaptersAddresses
	ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
	flags |= GAA_FLAG_INCLUDE_GATEWAYS;

	// default to unspecified address family (both)
	ULONG family = AF_UNSPEC;

	PIP_ADAPTER_ADDRESSES pAddresses = NULL;
	ULONG outBufLen = 0;

	PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
	IP_ADAPTER_PREFIX* pPrefix = NULL;

	getAdaptersAddressesLog("Calling GetAdaptersAddresses function with family = ");

	// First, check how much memory we need to allocate
	dwRetVal = GetAdaptersAddresses(family, flags, NULL, NULL, &outBufLen);
	CZSPAS_ASSERT(dwRetVal == ERROR_BUFFER_OVERFLOW); // This error is expected when passing NULL insteadl of pAddresses.

	pAddresses = (IP_ADAPTER_ADDRESSES*)HeapAlloc(GetProcessHeap(), 0, outBufLen);

	if (pAddresses == NULL) {
		CZSPAS_FATAL("Memory allocation failed for IP_ADAPTER_ADDRESSES struct");
		return {};
	}
	CZSPAS_SCOPE_EXIT{ HeapFree(GetProcessHeap(), 0, pAddresses); };

	dwRetVal = GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);
	if (dwRetVal != NO_ERROR)
	{
		CZSPAS_ERROR(detail::ErrorWrapper().msg().c_str());
		return {};
	}

	pCurrAddresses = pAddresses;
	while (pCurrAddresses)
	{
		NetworkAdapterInfo adapter;

		getAdaptersAddressesLog("\tLength of the IP_ADAPTER_ADDRESS struct: %ld\n", pCurrAddresses->Length);
		getAdaptersAddressesLog("\tIfIndex (IPv4 interface): %u\n", pCurrAddresses->IfIndex);
		getAdaptersAddressesLog("\tAdapter name: %s\n", pCurrAddresses->AdapterName);

		adapter.wname = pCurrAddresses->FriendlyName;
		adapter.unicast = walkAddresses(pCurrAddresses->FirstUnicastAddress, "Unicast", includeIPV6);
		adapter.anycast = walkAddresses(pCurrAddresses->FirstAnycastAddress, "Anycast", includeIPV6);
		adapter.multicast = walkAddresses(pCurrAddresses->FirstMulticastAddress, "Multicast", includeIPV6);
		adapter.gateways = walkAddresses(pCurrAddresses->FirstGatewayAddress, "Default Gateway", includeIPV6);

		auto unused = walkAddresses(pCurrAddresses->FirstDnsServerAddress, "DNS Server", includeIPV6);

		getAdaptersAddressesLog("\tDNS Suffix: %wS\n", pCurrAddresses->DnsSuffix);
		getAdaptersAddressesLog("\tDescription: %wS\n", pCurrAddresses->Description);
		getAdaptersAddressesLog("\tFriendly name: %wS\n", pCurrAddresses->FriendlyName);

		if (pCurrAddresses->PhysicalAddressLength != 0)
		{
			getAdaptersAddressesLog("\tPhysical address: ");
			for (i = 0; i < (int)pCurrAddresses->PhysicalAddressLength; i++)
			{
				if (i == (pCurrAddresses->PhysicalAddressLength - 1))
					getAdaptersAddressesLog("%.2X\n", (int)pCurrAddresses->PhysicalAddress[i]);
				else
					getAdaptersAddressesLog("%.2X-", (int)pCurrAddresses->PhysicalAddress[i]);
			}
		}
		getAdaptersAddressesLog("\tFlags: %ld\n", pCurrAddresses->Flags);
		getAdaptersAddressesLog("\tMtu: %lu\n", pCurrAddresses->Mtu);
		getAdaptersAddressesLog("\tIfType: %ld\n", pCurrAddresses->IfType);
		getAdaptersAddressesLog("\tOperStatus: %ld\n", pCurrAddresses->OperStatus);
		getAdaptersAddressesLog("\tIpv6IfIndex (IPv6 interface): %u\n", pCurrAddresses->Ipv6IfIndex);
		getAdaptersAddressesLog("\tZoneIndices (hex): ");
		for (i = 0; i < 16; i++) getAdaptersAddressesLog("%lx ", pCurrAddresses->ZoneIndices[i]);
		getAdaptersAddressesLog("\n");

		pPrefix = pCurrAddresses->FirstPrefix;
		if (pPrefix)
		{
			for (i = 0; pPrefix != NULL; i++) pPrefix = pPrefix->Next;
			getAdaptersAddressesLog("\tNumber of IP Adapter Prefix entries: %d\n", i);
		}
		else
			getAdaptersAddressesLog("\tNumber of IP Adapter Prefix entries: 0\n");

		getAdaptersAddressesLog("\n");

		if (pCurrAddresses->OperStatus==IfOperStatusUp || onlyStatusUp==false)
			res.push_back(adapter);

		pCurrAddresses = pCurrAddresses->Next;
	}

	return res;
}
#endif


} // namespace cz::spas

