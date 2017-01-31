//
// Excellent BSD socket tutorial:
// http://beej.us/guide/bgnet/
//
// Compatibility stuff (Windows vs Unix)
// https://tangentsoft.net/wskfaq/articles/bsd-compatibility.html
//
// Nice question/answer about socket states, including a neat state diagram:
//	http://stackoverflow.com/questions/5328155/preventing-fin-wait2-when-closing-socket
// Some differences between Windows and Linux:
// https://www.apriorit.com/dev-blog/221-crossplatform-linux-windows-sockets
//
// Windows loopback fast path:
// https://blogs.technet.microsoft.com/wincat/2012/12/05/fast-tcp-loopback-performance-and-low-latency-with-windows-server-2012-tcp-loopback-fast-path/

// #TODO
// - Instead of using SO_REUSEADDR, consider:
//		- Server should set SO_LINGER to 0
//			See:
//			http://stackoverflow.com/questions/3757289/tcp-option-so-linger-zero-when-its-required
//			http://www.serverframework.com/asynchronousevents/2011/01/time-wait-and-its-design-implications-for-protocols-and-scalable-servers.html
//		- Well behaved clients are the ones closing the connection
//

#pragma once

#ifdef _WIN32
	#define CZSPAS_WINSOCK 1
	#include <WinSock2.h>
	#include <WS2tcpip.h>
	#include <strsafe.h>
	#include <mstcpip.h>

#ifdef __MINGW32__
	// Bits and pieces missing in MingGW
	#ifndef SIO_LOOPBACK_FAST_PATH
		#define SIO_LOOPBACK_FAST_PATH              _WSAIOW(IOC_VENDOR,16)
	#endif
#endif

#elif __linux__
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <netinet/ip.h>
	#include <netinet/tcp.h>
	#include <arpa/inet.h>
	#include <unistd.h>
	#include <fcntl.h>
#endif

#include <set>
#include <memory>
#include <functional>
#include <atomic>
#include <chrono>
#include <assert.h>
#include <unordered_map>
#include <mutex>
#include <future>
#include <queue>
#include <stdio.h>
#include <cstdarg>
#include <string.h>

// Windows defines a min/max macro, interferes with STL
#ifdef max
	#undef max
	#undef min
#endif

#ifdef _WIN32
	#define CZSPAS_DEBUG_BREAK __debugbreak
#else
	#define CZSPAS_DEBUG_BREAK __builtin_trap
#endif

namespace cz
{
namespace spas
{

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

struct DefaultLog
{
	static void out(bool fatal, const char* type, const char* fmt, ...)
	{
		char buf[512];
		copyStrToFixedBuffer(buf, type);
		va_list args;
		va_start(args, fmt);
		vsnprintf(buf + strlen(buf), sizeof(buf) - strlen(buf) - 1, fmt, args);
		va_end(args);
		printf("%s\n",buf);
		if (fatal)
		{
			CZSPAS_DEBUG_BREAK();
			exit(1);
		}
	}
};

#ifndef CZSPAS_INFO
	#define CZSPAS_INFO(fmt, ...) DefaultLog::out(false, "Info: ", fmt, ##__VA_ARGS__)
#endif
#ifndef CZSPAS_WARN
	#define CZSPAS_WARN(fmt, ...) DefaultLog::out(false, "Warning: ", fmt, ##__VA_ARGS__)
#endif
#ifndef CZSPAS_ERROR
	#define CZSPAS_ERROR(fmt, ...) DefaultLog::out(false, "Error: ", fmt, ##__VA_ARGS__)
#endif
#ifndef CZSPAS_FATAL
	#define CZSPAS_FATAL(fmt, ...) DefaultLog::out(true, "Fatal: ", fmt, ##__VA_ARGS__)
#endif

#ifndef CZSPAS_ASSERT
	#define CZSPAS_ASSERT(expr) \
		if (!(expr)) CZSPAS_FATAL(#expr)
#endif


struct Error
{
	enum class Code
	{
		Success,
		Cancelled,
		ConnectionClosed,
		ConnectFailed,
		Other
	};

	Error(Code c = Code::Success) : code(c) {}
	Error(Code c, const char* msg) : code(c)
	{
		setMsg(msg);
	}
	Error(Code c, const std::string& msg) : code(c)
	{
		setMsg(msg.c_str());
	}

	const char* msg() const
	{
		if (optionalMsg)
			return optionalMsg->c_str();
		switch (code)
		{
			case Code::Success: return "Success";
			case Code::Cancelled: return "Cancelled";
			case Code::ConnectionClosed: return "ConnectionClosed";
			case Code::ConnectFailed: return "ConnectFailed";
			default: return "Unknown";
		}
	}

	void setMsg(const char* msg)
	{
		// Always create a new one, since it might be shared by other instances
		optionalMsg = std::make_shared<std::string>(msg);
	}

	//! Check if there is an error
	// Note that it returns true IF THERE IS AN ERROR, not the other way around.
	// This makes for shorter code
	operator bool() const
	{
		return code != Code::Success;
	}

	Code code;
	std::shared_ptr<std::string> optionalMsg;
};

class Acceptor;
class Socket;
class Service;
using ConnectHandler = std::function<void(const Error&)>;
using TransferHandler = std::function<void(const Error& ec, int bytesTransfered)>;
using AcceptHandler = std::function<void(const Error& ec)>;

#if _WIN32
	using SocketHandle = SOCKET;
	#define CZSPAS_INVALID_SOCKET INVALID_SOCKET
	#define CZSPAS_SOCKET_ERROR SOCKET_ERROR
#else
	using SocketHandle = int;
	#define CZSPAS_INVALID_SOCKET -1
	#define CZSPAS_SOCKET_ERROR -1
#endif


namespace details
{
	// Checks if a specified "Func" type is callable and with the specified signature
	template <typename, typename, typename = void>
	struct check_signature : std::false_type {};

	template <typename Func, typename Ret, typename... Args>
	struct check_signature<
		Func, Ret(Args...),
		typename std::enable_if_t<
			std::is_convertible<decltype(std::declval<Func>()(std::declval<Args>()...)), Ret>::value, void>>
		: std::true_type
	{
	};

	template<typename H>
	using IsTransferHandler = std::enable_if_t<check_signature<H, void(const Error&, int)>::value>;
	template<typename H>
	using IsSimpleHandler = std::enable_if_t<check_signature<H, void()>::value>;
	template<typename H>
	using IsAcceptHandler = std::enable_if_t<details::check_signature<H, void(const Error&)>::value>;

	class ErrorWrapper
	{
	public:
#if CZSPAS_WINSOCK
		static std::string getWin32ErrorMsg(DWORD err = ERROR_SUCCESS, const char* funcname = nullptr)
		{
			LPVOID lpMsgBuf;
			LPVOID lpDisplayBuf;
			if (err == ERROR_SUCCESS)
				err = GetLastError();

			FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				err,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(char*)&lpMsgBuf,
				0,
				NULL);

			int funcnameLength = funcname ? (int)strlen(funcname) : 0;
			lpDisplayBuf =
				(LPVOID)LocalAlloc(LMEM_ZEROINIT, (strlen((char*)lpMsgBuf) + funcnameLength + 50));
			StringCchPrintfA(
				(char*)lpDisplayBuf,
				LocalSize(lpDisplayBuf),
				"%s failed with error %d: %s",
				funcname ? funcname : "",
				err,
				lpMsgBuf);

			std::string ret = (char*)lpDisplayBuf;
			LocalFree(lpMsgBuf);
			LocalFree(lpDisplayBuf);

			// Remove the \r\n at the end
			while (ret.size() && ret.back() < ' ')
				ret.pop_back();

			return ret;
		}

		ErrorWrapper() { err = WSAGetLastError(); }
		std::string msg() const { return getWin32ErrorMsg(err); }
		bool isBlockError() const { return err == WSAEWOULDBLOCK; }
		int getCode() const { return err; };
#else
		ErrorWrapper() { err = errno; }
		bool isBlockError() const { return err == EAGAIN || err == EWOULDBLOCK || err == EINPROGRESS; }
		// #TODO Build custom error depending on the error number
		std::string msg() const { return strerror(err); }
		int getCode() const { return err; };
#endif

		Error getError() const { return Error(Error::Code::Other, msg()); }
	private:
		int err;
	};

	struct utils
	{
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
			int status =
				WSAIoctl(
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
					// This system is not Windows Windows Server 2012, and the call is not supported.
					// Do nothing
				}
				else 
				{
					CZSPAS_FATAL(err.msg().c_str());
				}
			}
#endif
		}

		static void closeSocket(SocketHandle s)
		{
			if (s == CZSPAS_INVALID_SOCKET)
				return;
#if _WIN32
			::shutdown(s, SD_BOTH);
			::closesocket(s);
#else
			::shutdown(s, SHUT_RDWR);
			::close(s);
#endif
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
				CZSPAS_FATAL(ErrorWrapper().msg().c_str());
		}

		static void setReuseAddress(SocketHandle s)
		{
			int optval = 1;
			int res = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&optval, sizeof(optval));
			if (res != 0)
				CZSPAS_FATAL(ErrorWrapper().msg().c_str());
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
				return addrToPair(addr);
			else
			{
				CZSPAS_FATAL(ErrorWrapper().msg().c_str());
				return std::make_pair("", 0);
			}
		}

		static std::pair<std::string, int> getRemoteAddr(SocketHandle s)
		{
			sockaddr_in addr;
			socklen_t size = sizeof(addr);
			if (getpeername(s, (sockaddr*)&addr, &size) != CZSPAS_SOCKET_ERROR)
				return addrToPair(addr);
			else
			{
				CZSPAS_FATAL(ErrorWrapper().msg().c_str());
				return std::make_pair("", 0);
			}
		}
	};

#if _WIN32
	struct WSAInstance
	{
		WSAInstance()
		{
			WORD wVersionRequested = MAKEWORD(2, 2);
			WSADATA wsaData;
			int err = WSAStartup(wVersionRequested, &wsaData);
			if (err != 0)
				CZSPAS_FATAL(ErrorWrapper().msg().c_str());

			if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
			{
				WSACleanup();
				CZSPAS_FATAL("Could not find a usable version of Winsock.dll");
			}
		}
		~WSAInstance()
		{
			WSACleanup();
		}
	};
#endif

	class ServiceData;
	//////////////////////////////////////////////////////////////////////////
	// BaseSocket
	//////////////////////////////////////////////////////////////////////////
	class BaseSocket
	{
	public:
		BaseSocket(details::ServiceData& owner) : m_owner(owner) {}
		virtual ~BaseSocket()
		{
			releaseHandle();
		}

		SocketHandle getHandle()
		{
			return m_s;
		}

	protected:

		BaseSocket(const BaseSocket&) = delete;
		void operator=(const BaseSocket&) = delete;

		friend Acceptor;
		bool isValid() const
		{
			return m_s != CZSPAS_INVALID_SOCKET;
		}

		void releaseHandle()
		{
			details::utils::closeSocket(m_s);
			m_s = CZSPAS_INVALID_SOCKET;
		}

		details::ServiceData& m_owner;
		SocketHandle m_s = CZSPAS_INVALID_SOCKET;
	};

	// This is not part of the Service class, so that we can break the circular dependency
	// between Acceptor/Socket and Service
	class ServiceData
	{
	public:
		ServiceData()
		{
		}

	protected:

#if _WIN32
		details::WSAInstance m_wsaInstance;
#endif
		std::unique_ptr<BaseSocket> m_signalIn;
		std::unique_ptr<BaseSocket> m_signalOut;

	};
} // namespace details


//////////////////////////////////////////////////////////////////////////
// Socket
//////////////////////////////////////////////////////////////////////////
class Socket : public details::BaseSocket
{
public:

	Socket(details::ServiceData& serviceData)
		: details::BaseSocket(serviceData)
	{
	}

	virtual ~Socket()
	{
	}

	//! Synchronous connect
	Error connect(const char* ip, int port)
	{
		CZSPAS_ASSERT(!isValid());

		CZSPAS_INFO("Socket %p: Connect(%s,%d)", this, ip, port);
		m_s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (m_s == CZSPAS_INVALID_SOCKET)
		{
			auto ec = details::ErrorWrapper().getError();
			CZSPAS_ERROR("Socket %p: %s", this, ec.msg());
			return ec;
		}

		// Enable any loopback optimizations (in case this socket is used in loopback)
		details::utils::optimizeLoopback(m_s);

		sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		inet_pton(AF_INET, ip, &(addr.sin_addr));
		if (::connect(m_s, (const sockaddr*)&addr, sizeof(addr)) == CZSPAS_SOCKET_ERROR)
		{
			auto ec = details::ErrorWrapper().getError();
			CZSPAS_ERROR("Socket %p: %s", this, ec.msg());
			releaseHandle();
			return ec;
		}

		details::utils::setBlocking(m_s, false);

		m_localAddr = details::utils::getLocalAddr(m_s);
		m_peerAddr = details::utils::getRemoteAddr(m_s);
		CZSPAS_INFO("Socket %p: Connected to %s:%d", this, m_peerAddr.first.c_str(), m_peerAddr.second);

		return Error();
	}
	 
	void asyncConnect(const char* ip, int port, ConnectHandler h, int timeoutMs = 200)
	{
		// #TODO : Fill me
	}

	template< typename H, typename = details::IsTransferHandler<H> >
	void asyncReceiveSome(char* buf, int len, H&& h)
	{
		// # TODO : Fill me
	}
	template< typename H, typename = details::IsTransferHandler<H> >
	void asyncSendSome(const char* buf, int len, H&& h)
	{
		// #TODO : Fill me
	}

	void close()
	{
	}

	const std::pair<std::string, int>& getLocalAddress() const
	{
		return m_localAddr;
	}

	const std::pair<std::string, int>& getPeerAddress() const
	{
		return m_peerAddr;
	}

protected:

	friend Acceptor;
	std::pair<std::string, int> m_localAddr;
	std::pair<std::string, int> m_peerAddr;
};

//////////////////////////////////////////////////////////////////////////
// Acceptor
//////////////////////////////////////////////////////////////////////////
class Acceptor : public details::BaseSocket
{
public:

	Acceptor(details::ServiceData& serviceData)
		: details::BaseSocket(serviceData)
	{
	}

	virtual ~Acceptor()
	{
	}

	//! Starts listening for new connections at the specified port
	/*
	\param port
		What port to listen on. If 0, the OS will pick a port from the dynamic range
	\param ec
		If an error occurs, this contains the error.
	\param backlog
		Size of the the connection backlog.
		Also, this is only an hint to the OS. It's not guaranteed.
	*/
	Error listen(int port, int backlog)
	{
		CZSPAS_ASSERT(!isValid());

		CZSPAS_INFO("Acceptor %p: listen(%d, %d)", this, port, backlog);
		
		m_s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (m_s == CZSPAS_INVALID_SOCKET)
		{
			auto ec = details::ErrorWrapper().getError();
			CZSPAS_ERROR("Acceptor %p: %s", this, ec.msg());
			return ec;
		}

		details::utils::setReuseAddress(m_s);

		CZSPAS_INFO("Acceptor %p: listening socket=%d", this, (int)m_s);
		sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
		if (
			(::bind(m_s, (const sockaddr*)&addr, sizeof(addr)) == CZSPAS_SOCKET_ERROR) ||
			(::listen(m_s, backlog) == CZSPAS_SOCKET_ERROR)
			)
		{
			auto ec = details::ErrorWrapper().getError();
			CZSPAS_ERROR("Acceptor %p: %s", this, ec.msg());
			releaseHandle();
			return ec;
		}

		// Enable any loopback optimizations (in case this socket is used in a loopback)
		details::utils::optimizeLoopback(m_s);

		m_localAddr = details::utils::getLocalAddr(m_s);

		// No error
		return Error();
	}

#if 0
	Error accept(Socket& sock, int timeoutMs = -1)
	{
		CZSPAS_ASSERT(isValid());
		CZSPAS_ASSERT(!sock.isValid());

		sockaddr_in addr;
		socklen_t size = sizeof(addr);
		sock.m_s = ::accept(m_s, (struct sockaddr*)&addr, &size);
		if (sock.m_s == CZSPAS_INVALID_SOCKET)
		{
			auto ec = details::ErrorWrapper().getError();
			CZSPAS_ERROR("Acceptor %p: %s", ec.msg());
			sock.releaseHandle();
		}

		sock.m_localAddr = details::utils::getLocalAddr(sock.m_s);
		sock.m_peerAddr = details::utils::getRemoteAddr(sock.m_s);
		details::utils::setBlocking(sock.m_s, false);
		CZSPAS_INFO("Acceptor %p: Socket %d connected to %s:%d, socket %d",
			this, (int)sock.m_s, sock.m_peerAddr.first.c_str(), sock.m_peerAddr.second);

		// No error
		return Error();
	}
#else
	Error accept(Socket& sock, int timeoutMs = -1)
	{
		CZSPAS_ASSERT(isValid());
		CZSPAS_ASSERT(!sock.isValid());

		timeval timeout{ 0,0 };
		if (timeoutMs != -1)
		{
			timeout.tv_sec = static_cast<long>((long)(timeoutMs) / 1000);
			timeout.tv_usec = static_cast<long>(((long)(timeoutMs) % 1000)*1000);
		}

		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(m_s, &fds);
		auto res = ::select((int)m_s + 1, &fds, NULL, NULL, timeoutMs == -1 ? NULL : &timeout);

		if (res == CZSPAS_SOCKET_ERROR) {
			auto ec = details::ErrorWrapper().getError();
			CZSPAS_ERROR("Acceptor %p: %s", this, ec.msg());
            return ec;
		}
		else if (res == 0) {
			return Error(Error::Code::Cancelled);
		}

		CZSPAS_ASSERT(res == 1);
		CZSPAS_ASSERT(FD_ISSET(m_s, &fds));

		sockaddr_in addr;
		socklen_t size = sizeof(addr);
		sock.m_s = ::accept(m_s, (struct sockaddr*)&addr, &size);
		if (sock.m_s == CZSPAS_INVALID_SOCKET)
		{
			sock.releaseHandle();
			auto ec = details::ErrorWrapper().getError();
			CZSPAS_ERROR("Acceptor %p: %s", this, ec.msg());
			return ec;
		}

		sock.m_localAddr = details::utils::getLocalAddr(sock.m_s);
		sock.m_peerAddr = details::utils::getRemoteAddr(sock.m_s);
		details::utils::setBlocking(sock.m_s, false);
		CZSPAS_INFO("Acceptor %p: Socket %p connected to %s:%d", this, &sock, sock.m_peerAddr.first.c_str(),
		            sock.m_peerAddr.second);

		// No error
		return Error();
	}

#endif

	template< typename H, typename = details::IsAcceptHandler<H> >
	void asyncAccept(Socket& sock, H&& h)
	{
		// #TODO : Fill me
		m_h = std::move(h);

	}

	void close()
	{
		// #TODO : Fill me
	}

	const std::pair<std::string, int>& getLocalAddress() const
	{
		return m_localAddr;
	}

protected:

	// Called by Service
	void doAsyncAccept()
	{
	}

	std::pair<std::string, int> m_localAddr;
	AcceptHandler m_h;
};


//////////////////////////////////////////////////////////////////////////
// Service
//////////////////////////////////////////////////////////////////////////
class Service : public details::ServiceData
{
private:

public:
	Service()
	{
	}

	~Service()
	{
	}

	// \return
	//		false : We are shutting down, and no need to call again
	//		true  : We should call tick again
	bool tick()
	{
		return true;
	}

	void run()
	{
		while (tick()) { }
	}

	//! Interrupts any tick calls in progress, and marks the service as finishing
	void stop()
	{
		// #TODO : Fill me
	}

	// Request to invoke the specified handler
	// The handler is NOT called from inside this function.
	template< typename H, typename = details::IsSimpleHandler<H> >
	void post(H&& handler)
	{
		// #TODO : Fill me
	}

	// Request to invoke the specified handler
	// The handler can be invoked from inside this function (if the current thread is executing tick)
	template< typename H, typename = details::IsSimpleHandler<H> >
	void dispatch(H&& handler)
	{
		// #TODO : Fill me
	}

protected:

};

} // namespace spas
} // namespace cz
