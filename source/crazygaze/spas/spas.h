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
//
// Notes on WSAPoll
//	https://blogs.msdn.microsoft.com/wndp/2006/10/26/wsapoll-a-new-winsock-api-to-simplify-porting-poll-applications-to-winsock/
//	Also has some tips how to write code for IPv6
//	- WSAPoll() is not exactly like poll(). It has a couple of bugs that microsoft never fixed. Example:
//		- Doesn't report failed connections. (E.g: A connect attempt to an address&port without listener and timeout -1 will block forever):
//			https://social.msdn.microsoft.com/Forums/windowsdesktop/en-US/18769abd-fca0-4d3c-9884-1a38ce27ae90/wsapoll-and-nonblocking-connects-to-nonexistent-ports?forum=wsk
//
// Good answer about SO_REUSEADDR:
// http://stackoverflow.com/questions/14388706/socket-options-so-reuseaddr-and-so-reuseport-how-do-they-differ-do-they-mean-t
//
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
	#define SPAS_WINSOCK 1
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
	#include <poll.h>
	#include <unistd.h>
	#include <fcntl.h>
#endif

#include <set>
#include <memory>
#include <functional>
#include <atomic>
#include <chrono>
#include <assert.h>
#include <limits.h>
#include <unordered_map>
#include <mutex>
#include <future>
#include <queue>
#include <stdio.h>
#include <cstdarg>
#include <string.h>
#include <algorithm>

// Windows defines a min/max macro, interferes with STL
#ifdef max
	#undef max
	#undef min
#endif

#ifdef _WIN32
	#define SPAS_DEBUG_BREAK __debugbreak
#else
	#define SPAS_DEBUG_BREAK __builtin_trap
#endif

namespace cz
{
namespace spas
{

// Forward declarations
class Acceptor;
class Socket;
class Service;

#ifndef SPAS_INFO
	#define SPAS_INFO(fmt, ...) detail::DefaultLog::out(false, "Info: ", fmt, ##__VA_ARGS__)
#endif
#ifndef SPAS_WARN
	#define SPAS_WARN(fmt, ...) detail::DefaultLog::out(false, "Warning: ", fmt, ##__VA_ARGS__)
#endif
#ifndef SPAS_ERROR
	#define SPAS_ERROR(fmt, ...) detail::DefaultLog::out(false, "Error: ", fmt, ##__VA_ARGS__)
#endif
#ifndef SPAS_FATAL
	#define SPAS_FATAL(fmt, ...) detail::DefaultLog::out(true, "Fatal: ", fmt, ##__VA_ARGS__)
#endif

#ifndef SPAS_ASSERT
	#define SPAS_ASSERT(expr) \
		if (!(expr)) SPAS_FATAL(#expr)
#endif

#if _WIN32
	using SocketHandle = SOCKET;
	#define SPAS_INVALID_SOCKET INVALID_SOCKET
	#define SPAS_SOCKET_ERROR SOCKET_ERROR
#else
	using SocketHandle = int;
	#define SPAS_INVALID_SOCKET -1
	#define SPAS_SOCKET_ERROR -1
#endif

struct Error
{
	// #TODO : Revise if all error codes are being used (and used in the right places)
	enum class Code
	{
		Success,
		Cancelled,
		Timeout,
		ConnectionClosed,
		InvalidSocket,
		Other,
		Max // Only used internally
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
			case Code::Timeout: return "Timeout";
			case Code::ConnectionClosed: return "ConnectionClosed";
			case Code::InvalidSocket: return "InvalidSocket";
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

using ConnectHandler = std::function<void(const Error&)>;
using TransferHandler = std::function<void(const Error& ec, size_t transfered)>;
using AcceptHandler = std::function<void(const Error& ec)>;


namespace detail
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
				SPAS_DEBUG_BREAK();
				exit(1);
			}
		}
	};

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
	using IsTransferHandler = std::enable_if_t<check_signature<H, void(const Error&, size_t)>::value>;
	template<typename H>
	using IsSimpleHandler = std::enable_if_t<check_signature<H, void()>::value>;
	template<typename H>
	using IsAcceptHandler = std::enable_if_t<detail::check_signature<H, void(const Error&)>::value>;

	class ErrorWrapper
	{
	public:
#if SPAS_WINSOCK
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
			SPAS_ASSERT(s != SPAS_INVALID_SOCKET);
#if _WIN32
			// 0: Blocking. !=0 : Non-blocking
			u_long mode = blocking ? 0 : 1;
			int res = ioctlsocket(s, FIONBIO, &mode);
			if (res != 0)
				SPAS_FATAL(ErrorWrapper().msg().c_str());
#else
			int flags = fcntl(s, F_GETFL, 0);
			if (flags <0)
				SPAS_FATAL(ErrorWrapper().msg().c_str());
			flags = blocking ? (flags&~O_NONBLOCK) : (flags|O_NONBLOCK);
			if (fcntl(s, F_SETFL, flags) != 0)
				SPAS_FATAL(ErrorWrapper().msg().c_str());
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

			if (status==SPAS_SOCKET_ERROR)
			{
				ErrorWrapper err;
				if (err.getCode() == WSAEOPNOTSUPP)
				{
					// This system is not Windows Windows Server 2012, and the call is not supported.
					// Do nothing
				}
				else 
				{
					SPAS_FATAL(err.msg().c_str());
				}
			}
#endif
		}

		static void closeSocket(SocketHandle& s, bool doshutdown=true)
		{
			if (s == SPAS_INVALID_SOCKET)
				return;
#if _WIN32
			if (doshutdown)
				::shutdown(s, SD_BOTH);
			::closesocket(s);
#else
			if (doshutdown)
				::shutdown(s, SHUT_RDWR);
			::close(s);
#endif
			s = SPAS_INVALID_SOCKET;
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
				SPAS_FATAL(ErrorWrapper().msg().c_str());
		}

		static void setReuseAddress(SocketHandle s)
		{
			int optval = 1;
			int res = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&optval, sizeof(optval));
			if (res != 0)
				SPAS_FATAL(ErrorWrapper().msg().c_str());
		}

		// Set the linger option, in seconds
		static void setLinger(SocketHandle s, bool enabled, u_short timeout)
		{
			linger l;
			l.l_onoff = enabled ? 1 : 0;
			l.l_linger = timeout;
			int res = setsockopt(s, SOL_SOCKET, SO_LINGER, (const char*)&l, sizeof(l));
			if (res != 0)
				SPAS_FATAL(ErrorWrapper().msg().c_str());
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
			if (getsockname(s, (sockaddr*)&addr, &size) != SPAS_SOCKET_ERROR && size == sizeof(addr))
				return addrToPair(addr);
			else
			{
				SPAS_FATAL(ErrorWrapper().msg().c_str());
				return std::make_pair("", 0);
			}
		}

		static std::pair<std::string, int> getRemoteAddr(SocketHandle s)
		{
			sockaddr_in addr;
			socklen_t size = sizeof(addr);
			if (getpeername(s, (sockaddr*)&addr, &size) != SPAS_SOCKET_ERROR)
				return addrToPair(addr);
			else
			{
				//SPAS_FATAL(ErrorWrapper().msg().c_str());
				return std::make_pair("", 0);
			}
		}

		//! Creates a socket and puts it into listen mode
		//
		// \param bindIp
		//		What IP to bind to.
		// \param port
		//		What port to listen on. If 0, the OS will pick a port from the dynamic range
		// \param ec
		//		If an error occurs, this contains the error.
		// \param backlog
		//		Size of the the connection backlog.
		//		Also, this is only an hint to the OS. It's not guaranteed.
		//
		static std::pair<Error, SocketHandle> createListenSocketEx(const char* bindIp, int port, int backlog, bool reuseAddr)
		{
			SocketHandle s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (s == SPAS_INVALID_SOCKET)
				return std::make_pair(detail::ErrorWrapper().getError(), s);

			if (reuseAddr)
				detail::utils::setReuseAddress(s);

			sockaddr_in addr;
			addr.sin_family = AF_INET;
			addr.sin_port = htons(port);
			if (bindIp)
				inet_pton(AF_INET, bindIp, &(addr.sin_addr));
			else
				addr.sin_addr.s_addr = htonl(INADDR_ANY);

			if (
				(::bind(s, (const sockaddr*)&addr, sizeof(addr)) == SPAS_SOCKET_ERROR) ||
				(::listen(s, backlog) == SPAS_SOCKET_ERROR)
				)
			{
				auto ec = detail::ErrorWrapper().getError();
				closeSocket(s);
				return std::make_pair(ec, SPAS_INVALID_SOCKET);
			}

			// Enable any loopback optimizations (in case this socket is used in a loopback)
			detail::utils::optimizeLoopback(s);

			return std::make_pair(Error(), s);
		}

		static std::pair<Error, SocketHandle> createListenSocket(int port)
		{
			return createListenSocketEx(nullptr, port, SOMAXCONN, false);
		}

		//! Synchronous connect
		static std::pair<Error, SocketHandle> createConnectSocket(const char* ip, int port)
		{
			SocketHandle s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (s == SPAS_INVALID_SOCKET)
				return std::make_pair(detail::ErrorWrapper().getError(), s);

			// Enable any loopback optimizations (in case this socket is used in loopback)
			detail::utils::optimizeLoopback(s);

			sockaddr_in addr;
			memset(&addr, 0, sizeof(addr));
			addr.sin_family = AF_INET;
			addr.sin_port = htons(port);
			inet_pton(AF_INET, ip, &(addr.sin_addr));
			if (::connect(s, (const sockaddr*)&addr, sizeof(addr)) == SPAS_SOCKET_ERROR)
			{
				auto ec = detail::ErrorWrapper().getError();
				closeSocket(s);
				return std::make_pair(ec, SPAS_INVALID_SOCKET);
			}

			detail::utils::setBlocking(s, false);
			return std::make_pair(Error(), s);
		}

		static std::pair<Error, SocketHandle> accept(SocketHandle& acceptor, int timeoutMs = -1)
		{
			SPAS_ASSERT(acceptor != SPAS_INVALID_SOCKET);

			timeval timeout{ 0,0 };
			if (timeoutMs != -1)
			{
				timeout.tv_sec = static_cast<long>((long)(timeoutMs) / 1000);
				timeout.tv_usec = static_cast<long>(((long)(timeoutMs) % 1000) * 1000);
			}

			fd_set fds;
			FD_ZERO(&fds);
			FD_SET(acceptor, &fds);
			auto res = ::select((int)acceptor + 1, &fds, NULL, NULL, timeoutMs == -1 ? NULL : &timeout);

			if (res == SPAS_SOCKET_ERROR) {
				return std::make_pair(detail::ErrorWrapper().getError(), SPAS_INVALID_SOCKET);
			}
			else if (res == 0) {
				return std::make_pair(Error(Error::Code::Timeout), SPAS_INVALID_SOCKET);
			}

			SPAS_ASSERT(res == 1);
			SPAS_ASSERT(FD_ISSET(acceptor, &fds));

			sockaddr_in addr;
			socklen_t size = sizeof(addr);
			SocketHandle s = ::accept(acceptor, (struct sockaddr*)&addr, &size);
			if (s == SPAS_INVALID_SOCKET)
				return std::make_pair(detail::ErrorWrapper().getError(), s);

			detail::utils::setBlocking(s, false);

			return std::make_pair(Error(), s);
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
				SPAS_FATAL(ErrorWrapper().msg().c_str());

			if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
			{
				WSACleanup();
				SPAS_FATAL("Could not find a usable version of Winsock.dll");
			}
		}
		~WSAInstance()
		{
			WSACleanup();
		}
	};
#endif

	struct SocketOperation;
	struct AcceptOperation;
	struct ConnectOperation;
	struct SendOperation;
	struct ReceiveOperation;

	class BaseService
	{
	};

	class BaseSocket
	{
	public:
		BaseSocket(detail::BaseService& owner)
			: m_owner(owner)
			, m_pendingAccept(false)
			, m_pendingConnect(false)
			, m_pendingSend(false)
			, m_pendingReceive(false)
		{
		}
		virtual ~BaseSocket()
		{
			SPAS_ASSERT(m_pendingAccept.load() == false);
			SPAS_ASSERT(m_pendingConnect.load() == false);
			SPAS_ASSERT(m_pendingSend.load() == false);
			SPAS_ASSERT(m_pendingReceive.load() == false);
		}

		//! Only to be used with care, if the user wants to access the underlying socket handle
		SocketHandle getHandle()
		{
			return m_s;
		}

		Service& getService()
		{
			return *((Service*)&m_owner);
		}

		void setLinger(bool enabled, unsigned short timeout)
		{
			detail::utils::setLinger(m_s, enabled, timeout);
		}

		// For internal use in the unit tests. DO NOT USE
		void _forceClose(bool doshutdown)
		{
			detail::utils::closeSocket(m_s, doshutdown);
		}

	protected:
		BaseSocket(const BaseSocket&) = delete;
		void operator=(const BaseSocket&) = delete;

		friend SocketOperation;
		friend AcceptOperation;
		friend ConnectOperation;
		friend SendOperation;
		friend ReceiveOperation;
		friend Acceptor;
		bool isValid() const
		{
			return m_s != SPAS_INVALID_SOCKET;
		}

		void resolveAddrs()
		{
			m_localAddr = detail::utils::getLocalAddr(m_s);
			m_peerAddr = detail::utils::getRemoteAddr(m_s);
		}

		detail::BaseService& m_owner;
		SocketHandle m_s = SPAS_INVALID_SOCKET;

		// Only for debugging: #TODO : Add a define to have it available only on Debug build
		// NOTE: In the Operation structs, these need to be set to false in both the destructor and BEFORE calling the user handler
		//		1. Its needed in the destructor, because the operation might be destroyed without calling the user handler (e.g: Cancelled)
		//		2. BEFORE calling the user handler, because from the handle the user might want to queue another operation of the same type
		std::atomic<bool> m_pendingAccept; 
		std::atomic<bool> m_pendingConnect;
		std::atomic<bool> m_pendingSend;
		std::atomic<bool> m_pendingReceive;

		std::pair<std::string, int> m_localAddr;
		std::pair<std::string, int> m_peerAddr;
	};

	struct Operation
	{
		Error ec;
		virtual ~Operation() { }
		virtual void exec(SocketHandle fd, bool hasPOLLHUP) = 0;
		virtual void callUserHandler() = 0;
	};

	struct PostOperation : Operation
	{
		std::function<void()> userHandler;
		template<typename H>
		PostOperation(H&& h)
			: userHandler(std::forward<H>(h)) {}
		virtual void exec(SocketHandle fd, bool hasPOLLHUP) override {}
		virtual void callUserHandler() { userHandler(); }
	};

	struct SocketOperation : public Operation
	{
		BaseSocket& owner;
		explicit SocketOperation(BaseSocket& owner) : owner(owner)
		{
		}
	};

	struct AcceptOperation : public SocketOperation
	{
		std::function<void(const Error& ec)> userHandler;
		BaseSocket& sock;

		template<typename H>
		AcceptOperation(BaseSocket& owner, BaseSocket& dst, H&& h)
			: SocketOperation(owner)
			, sock(dst)
			, userHandler(std::forward<H>(h))
		{
			owner.m_pendingAccept = true;
		}

		~AcceptOperation()
		{
			owner.m_pendingAccept = false;
		}

		virtual void exec(SocketHandle fd, bool hasPOLLHUP) override
		{
			sockaddr_in addr;
			socklen_t size = sizeof(addr);
			sock.m_s = ::accept(fd, (struct sockaddr*)&addr, &size);
			if (sock.m_s == SPAS_INVALID_SOCKET)
				ec = detail::ErrorWrapper().getError();
			else
			{
				detail::utils::setBlocking(sock.m_s, false);
				sock.resolveAddrs();
			}
		}

		virtual void callUserHandler() override
		{
			owner.m_pendingAccept = false;
			userHandler(ec);
		}
	};

	struct ConnectOperation : public SocketOperation
	{
		std::function<void(const Error& ec)> userHandler;

		template<typename H>
		ConnectOperation(BaseSocket& owner, H&& h)
			: SocketOperation(owner)
			, userHandler(std::forward<H>(h))
		{
			owner.m_pendingConnect = true;
		}

		~ConnectOperation()
		{
			owner.m_pendingConnect = false;
		}

		virtual void exec(SocketHandle fd, bool hasPOLLHUP) override
		{
			SPAS_ASSERT(fd == owner.getHandle());
			owner.resolveAddrs();
		}

		virtual void callUserHandler() override
		{
			owner.m_pendingConnect = false;
			userHandler(ec);
		}
	};

	struct TransferOperation : public SocketOperation
	{
		char* buf;
		size_t bufSize;
		size_t transfered = 0;
		std::function<void(const Error& ec, size_t transfered)> userHandler;

		template<typename H>
		TransferOperation(BaseSocket& owner, char* buf, size_t bufSize, H&& h)
			: SocketOperation(owner)
			, buf(buf)
			, bufSize(bufSize)
			, userHandler(std::forward<H>(h))
		{
		}

	};

	struct SendOperation : public TransferOperation
	{
		template<typename H>
		SendOperation(BaseSocket& owner, const char* buf, size_t bufSize, H&& h)
			: TransferOperation(owner, const_cast<char*>(buf), bufSize, std::forward<H>(h))
		{
			owner.m_pendingSend = true;
		}

		~SendOperation()
		{
			owner.m_pendingSend = false;
		}

		virtual void exec(SocketHandle fd, bool hasPOLLHUP) override
		{
			SPAS_ASSERT(fd == owner.getHandle());
			// The interface allows size_t, but the implementation only allows int
			int todo = bufSize > INT_MAX ? INT_MAX : static_cast<int>(bufSize);
			int flags = 0;
#if __linux__
			flags = MSG_NOSIGNAL;
#endif
			int len = ::send(fd, buf, todo, flags);
			if (len == SPAS_SOCKET_ERROR)
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
						SPAS_FATAL("Blocking not expected at this point.");
					}
				}
			}
			else
			{
				transfered = len;
			}
		}

		virtual void callUserHandler() override
		{
			owner.m_pendingSend = false;
			userHandler(ec, transfered);
		}
	};

	struct ReceiveOperation : public TransferOperation
	{
		template<typename H>
		ReceiveOperation(BaseSocket& owner, char* buf, size_t bufSize, H&& h)
			: TransferOperation(owner, buf, bufSize, std::forward<H>(h))
		{
			owner.m_pendingReceive = true;
		}

		~ReceiveOperation()
		{
			owner.m_pendingReceive = false;
		}

		virtual void exec(SocketHandle fd, bool hasPOLLHUP) override
		{
			SPAS_ASSERT(fd == owner.getHandle());
			// The interface allows size_t, but the implementation only allows int
			int todo = bufSize > INT_MAX ? INT_MAX : static_cast<int>(bufSize);
			int len = ::recv(fd, buf, todo, 0);
			if (len == SPAS_SOCKET_ERROR)
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
						SPAS_FATAL("Blocking not expected at this point.");
					}
				}
			}
			else if (len == 0) // A disconnect
			{
				// On Windows, we never get here, since WSAPoll doesn't work exactly the same way has poll, according to what I've seen with my tests
				// Example, while on a WSAPoll, when a peer disconnects, the following happens:
				//	- Windows:
				//		- WSAPoll reports an error (POLLHUP)
				//	- Linux:
				//		- poll reports ready to ready (success), and then recv reads 0 (which means the peer disconnected)
				ec = Error(Error::Code::ConnectionClosed);
			}
			else
			{
				transfered = len;
			}
		}

		virtual void callUserHandler() override
		{
			owner.m_pendingReceive = false;
			userHandler(ec, transfered);
		}
	};
		 

//////////////////////////////////////////////////////////////////////////
// Reactor interface
//////////////////////////////////////////////////////////////////////////

class Reactor
{
public:
	enum EventType
	{
		Read,
		Write,
		Max
	};

private:

#if _WIN32
	detail::WSAInstance m_wsaInstance;
#endif
	using Timepoint = std::chrono::time_point<std::chrono::high_resolution_clock>;

	struct OperationData
	{
		void cancel(Error::Code code, std::queue<std::unique_ptr<Operation>>& dst)
		{
			if (op)
			{
				op->ec = Error(code);
				dst.push(std::move(op));
			}
		}

		std::unique_ptr<Operation> op;
		Timepoint timeout = Timepoint::max();
	};

	struct SocketData
	{
		void cancel(Error::Code code, std::queue<std::unique_ptr<Operation>>& dst)
		{
			for (auto&& op : ops)
				op.cancel(code, dst);
		}

		OperationData ops[EventType::Max];
	};

	std::mutex m_mtx;
	SocketHandle m_signalIn;
	SocketHandle m_signalOut;
	std::vector<pollfd> m_fds;
	std::unordered_map<SocketHandle, SocketData> m_sockData;

	// Read as much data as possible from the signalIn socket
	void readInterrupt()
	{
		char buf[64];
		bool done = false;
		while (!done)
		{
			if (recv(m_signalIn, buf, sizeof(buf), 0) == SPAS_SOCKET_ERROR)
			{
				detail::ErrorWrapper err;
				if (err.isBlockError()) // This is expected, and it means there is no more data to read
				{
					done = true;
				}
				else
				{
					SPAS_FATAL("Reactor %p: %s", this, err.msg().c_str());
				}
			}
		}
	}

	static void setFd(pollfd& fd, const SocketData& data, Reactor::EventType type, Timepoint& timeout)
	{
		auto&& o = data.ops[type];
		if (!o.op)
			return;
		fd.events |= (type == Reactor::EventType::Read) ? POLLRDNORM : POLLWRNORM;
		if (o.timeout < timeout)
			timeout = o.timeout;
	}

	// Return true if the operation was left empty (e.g: executed/timed out)
	bool processEventsHelper(SocketHandle fd, OperationData& opdata, int ready, bool hasPOLLHUP, Timepoint now,
	                         std::queue<std::unique_ptr<Operation>>& dst)
	{
		if (!opdata.op)
			return true;

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
			return false;
	}

	void processEvents(std::queue<std::unique_ptr<Operation>>& dst)
	{
		auto now = std::chrono::high_resolution_clock::now();
		for (auto fdit = m_fds.begin() + 1; fdit != m_fds.end(); ++fdit)
		{
			auto&& fd = *fdit;
			auto it = m_sockData.find(fd.fd);
			if (it==m_sockData.end())
				continue; // Socket data not present anymore (E.g: Operations were cancelled while in the poll function)

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
				empty = empty && processEventsHelper(it->first, it->second.ops[EventType::Write],
					fd.revents & POLLWRNORM, hasPOLLHUP, now, dst);
				if (empty)
					m_sockData.erase(it);
			}
		}
	}

public:

	Reactor()
	{

		// Create a listening socket on a port picked by the OS (because we passed 0 as port)
		auto acceptor = utils::createListenSocketEx("127.0.0.1", 0, 1, false);
		// If this fails, then the OS probably ran out of resources (e.g: Too many connections or too many connection 
		// on TIME_WAIT)
		SPAS_ASSERT(!acceptor.first);

		auto connectFt = std::async(std::launch::async, [this, port = detail::utils::getLocalAddr(acceptor.second).second]
		{
			auto res = detail::utils::createConnectSocket("127.0.0.1", port);
			// Same as above. If this fails, then the OS ran out of resources
			SPAS_ASSERT(!res.first);
			return res.second;
		});

		auto res = detail::utils::accept(acceptor.second);
		detail::utils::closeSocket(acceptor.second);
		SPAS_ASSERT(!res.first);
		m_signalIn = res.second;
		m_signalOut = connectFt.get();
	}

	~Reactor()
	{
		m_sockData.clear();
		// To avoid the TIME_WAIT, we do the following:
		// 1. Disable lingering on the client socket (m_signalOut)
		// 2. Close client socket
		// 3. Close server side socket (m_signalIn). This the other socket was the one initiating the shutdown,
		//    this one doesn't go into TIME_WAIT
		detail::utils::setLinger(m_signalOut, true, 0);
		detail::utils::closeSocket(m_signalOut, false);
		detail::utils::closeSocket(m_signalIn, false);
	}

	void interrupt()
	{
		char buf = 0;
		int flags = 0;
#if __linux__
		flags = MSG_NOSIGNAL;
#endif
		if (::send(m_signalOut, &buf, 1, flags) != 1)
			SPAS_FATAL("Reactor %p", this, detail::ErrorWrapper().msg().c_str());
	}

	void addOperation(SocketHandle fd, EventType type, std::unique_ptr<Operation> op, int timeoutMs)
	{
		std::unique_lock<std::mutex> lk(m_mtx);
		auto&& o = m_sockData[fd].ops[type];
		o.op = std::move(op);
		o.timeout = timeoutMs == -1 ? Timepoint::max()
		                            : std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(timeoutMs);
		interrupt();
	}

	void cancel(SocketHandle fd, std::queue<std::unique_ptr<Operation>>& dst)
	{
		std::unique_lock<std::mutex> lk(m_mtx);
		auto it = m_sockData.find(fd);
		if (it == m_sockData.end())
			return; // No operations for this socket found
		it->second.cancel(Error::Code::Cancelled, dst);
		m_sockData.erase(it);
		interrupt();
	}

	void runOnce(std::queue<std::unique_ptr<Operation>>& dst)
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
			SPAS_ASSERT(m_fds.back().events != 0);
		}

		lk.unlock();

		int timeoutMs = -1;
		if (timeoutPoint != Timepoint::max())
		{
			timeoutMs = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(timeoutPoint - std::chrono::high_resolution_clock::now()).count());
			if (timeoutMs < 0)
				timeoutMs = 0;
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

		if (res == SPAS_SOCKET_ERROR)
		{
			SPAS_FATAL("Reactor %p: %s", this, detail::ErrorWrapper().msg().c_str());
		}
		else
		{
			SPAS_ASSERT(res >= 0);
			processEvents(dst);
		}
	}
};

} // namespace detail

//////////////////////////////////////////////////////////////////////////
//	Service interface
//////////////////////////////////////////////////////////////////////////
class Service : public detail::BaseService
{
public:
	Service()
	{
	}
	~Service()
	{
	}

	template<typename H, typename = detail::IsSimpleHandler<H>>
	void post(H&& h)
	{
		std::lock_guard<std::mutex> lk(m_mtx);
		m_ready.push(std::make_unique<detail::PostOperation>(std::forward<H>(h)));
		m_reactor.interrupt();
	}

	void stop()
	{
		m_stopping = true;
		m_reactor.interrupt();
	}

	void run(bool loop=true)
	{
		// NOTE: At first, I was resetting m_stopping to false here, but that is problematic:
		// E.g:
		// - One thread id created to call run
		// - Another thread calls stop() before the first thread has a chance to call run().
		// - The stop would be ignored (since we would be setting m_stopping to true here.

		while (loop && !m_stopping)
		{
			{
				std::lock_guard<std::mutex> lk(m_mtx);
				std::swap(m_tmpready, m_ready);
			}
			while (m_tmpready.size())
			{
				m_tmpready.front()->callUserHandler();
				m_tmpready.pop();
			}

			m_reactor.runOnce(m_tmpready);

			while (m_tmpready.size())
			{
				m_tmpready.front()->callUserHandler();
				m_tmpready.pop();
			}
		}
	}

private:

	void cancel(SocketHandle fd)
	{
		std::lock_guard<std::mutex> lk(m_mtx);
		m_reactor.cancel(fd, m_ready);
	}

	void post(std::unique_ptr<detail::Operation> op)
	{
		std::lock_guard<std::mutex> lk(m_mtx);
		m_ready.push(std::move(op));
		m_reactor.interrupt();
	}

	void addOperation(SocketHandle fd, detail::Reactor::EventType type, std::unique_ptr<detail::Operation> op, int timeoutMs)
	{
		m_reactor.addOperation(fd, type, std::move(op), timeoutMs);
	}

	friend class Acceptor;
	friend class Socket;
	std::mutex m_mtx;
	detail::Reactor m_reactor;
	std::queue<std::unique_ptr<detail::Operation>> m_ready;
	std::queue<std::unique_ptr<detail::Operation>> m_tmpready;
	std::atomic<bool> m_stopping{false};
};

//////////////////////////////////////////////////////////////////////////
//	Socket interface
//////////////////////////////////////////////////////////////////////////
class Socket : public detail::BaseSocket
{
public:
	Socket(Service& service) : detail::BaseSocket(service)
	{
	}

	~Socket()
	{
		detail::utils::closeSocket(m_s);
	}

	//! Synchronous connect
	Error connect(const char* ip, int port)
	{
		SPAS_ASSERT(!isValid());

		SPAS_INFO("Socket %p: Connect(%s,%d)", this, ip, port);
		auto res = detail::utils::createConnectSocket(ip, port);
		if (res.first)
		{
			SPAS_ERROR("Socket %p: %s", this, res.first.msg());
			return res.first;
		}
		m_s = res.second;
		resolveAddrs();
		SPAS_INFO("Socket %p: Connected to %s:%d", this, m_peerAddr.first.c_str(), m_peerAddr.second);
		return Error();
	}

	void cancel()
	{
		if (isValid())
			getService().cancel(m_s);
	}

	void asyncConnect(const char* ip, int port, int timeoutMs, ConnectHandler h)
	{
		SPAS_ASSERT(!isValid());
		SPAS_ASSERT(m_pendingConnect.load()==false && "There is already a pending connect operation");
		SPAS_INFO("Socket %p: asyncConnect(%s,%d, H, %d)", this, ip, port, timeoutMs);

		auto op = std::make_unique<detail::ConnectOperation>(*this, std::move(h));

		m_s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (m_s == SPAS_INVALID_SOCKET)
		{
			op->ec = detail::ErrorWrapper().getError();
			SPAS_ERROR("Socket %p: %s", this, op->ec.msg());
			getService().post(std::move(op));
			return;
		}

		// Enable any loopback optimizations (in case this socket is used in loopback)
		detail::utils::optimizeLoopback(m_s);
		// Set to non-blocking, so we can do an asynchronous connect
		detail::utils::setBlocking(m_s, false);

		sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		inet_pton(AF_INET, ip, &(addr.sin_addr));

		if (::connect(m_s, (const sockaddr*)&addr, sizeof(addr)) == SPAS_SOCKET_ERROR)
		{
			detail::ErrorWrapper err;
			if (err.isBlockError())
			{
				// Normal behavior.
				// A asynchronous connect is done when we receive a write event on the socket
				getService().addOperation(m_s, detail::Reactor::EventType::Write, std::move(op), timeoutMs);
			}
			else
			{
				// Any other error is a real error, so queue the handler for execution
				//detail::utils::closeSocket(m_s);
				op->ec = err.getError();
				getService().post(std::move(op));
			}
		}
		else
		{
			// It may happen that the connect succeeds right away ?
			// If that happens, we can still wait for the reactor to detect the "ready to write" event.
			getService().addOperation(m_s, detail::Reactor::EventType::Write, std::move(op), timeoutMs);
		}
	}

	template< typename H, typename = detail::IsTransferHandler<H> >
	void asyncSendSome(const char* buf, size_t len, int timeoutMs, H&& h)
	{
		SPAS_ASSERT(isValid());
		SPAS_ASSERT(m_pendingSend.load()==false && "There is already a pending send operation");
		auto op = std::make_unique<detail::SendOperation>(*this, buf, len, std::forward<H>(h));
		getService().addOperation(m_s, detail::Reactor::EventType::Write, std::move(op), timeoutMs);
	}

	template< typename H, typename = detail::IsTransferHandler<H> >
	void asyncReceiveSome(char* buf, size_t len, int timeoutMs, H&& h)
	{
		SPAS_ASSERT(isValid());
		SPAS_ASSERT(m_pendingReceive.load()==false && "There is already a pending receive operation");
		auto op = std::make_unique<detail::ReceiveOperation>(*this, buf, len, std::forward<H>(h));
		getService().addOperation(m_s, detail::Reactor::EventType::Read, std::move(op), timeoutMs);
	}
private:
};

//////////////////////////////////////////////////////////////////////////
//	Acceptor interface
//////////////////////////////////////////////////////////////////////////
class Acceptor : public detail::BaseSocket
{
public:
	Acceptor(Service& service)
		: detail::BaseSocket(service)
	{
	}

	virtual ~Acceptor()
	{
		// Close the socket without calling shutdown, and setting linger to 0, so it doesn't linger around and we can
		// run another server right after
		// Not sure this is necessary for listening sockets. ;(
		if (m_s != SPAS_INVALID_SOCKET)
			detail::utils::setLinger(m_s, true, 0);
		detail::utils::closeSocket(m_s, false);
	}

	//! Starts listening for new connections at the specified port
	/*
	\param port
		What port to listen on. If 0, the OS will pick a port from the dynamic range
	\param ec
		If an error occurs, this contains the error.
	\param backlog
		Size of the connection backlog.
		This is only an hint to the OS. It's not guaranteed.
	*/
	Error listenEx(const char* bindIp, int port, int backlog, bool reuseAddr)
	{
		SPAS_ASSERT(!isValid());
		SPAS_INFO("Acceptor %p: listen(%d, %d)", this, port, backlog);

		auto res = detail::utils::createListenSocketEx(bindIp, port, backlog, reuseAddr);
		if (res.first)
		{
			SPAS_ERROR("Acceptor %p: %s", this, res.first.msg());
			return res.first;
		}
		m_s = res.second;

		resolveAddrs();
		// No error
		return Error();
	}

	Error listen(int port)
	{
		bool reuseAddr = false;
#if __linux__
        reuseAddr = true;
#endif
		return listenEx(nullptr, port, SOMAXCONN, reuseAddr);
	}

	Error accept(Socket& sock, int timeoutMs = -1)
	{
		SPAS_ASSERT(isValid());
		SPAS_ASSERT(!sock.isValid());

		auto res = detail::utils::accept(m_s, timeoutMs);
		if (res.first)
		{
			SPAS_ERROR("Acceptor %p: %s", this, res.first.msg());
			return res.first;
		}
		sock.m_s = res.second;
		sock.resolveAddrs();
		SPAS_INFO("Acceptor %p: Socket %p connected to %s:%d", this, &sock, sock.m_peerAddr.first.c_str(),
		            sock.m_peerAddr.second);

		// No error
		return Error();
	}

	template< typename H, typename = detail::IsAcceptHandler<H> >
	void asyncAccept(Socket& sock, int timeoutMs, H&& h)
	{
		SPAS_ASSERT(isValid());
		SPAS_ASSERT(!sock.isValid());
		SPAS_ASSERT(m_pendingAccept.load()==false && "There is already a pending accept operation");
		auto op = std::make_unique<detail::AcceptOperation>(*this, sock, std::forward<H>(h));
		getService().addOperation(m_s, detail::Reactor::EventType::Read, std::move(op), timeoutMs);
	}

	void cancel()
	{
		if (isValid())
			getService().cancel(m_s);
	}

private:

};

namespace detail
{
	template< typename H, typename = detail::IsTransferHandler<H> >
	void asyncSendHelper(Socket& sock, const char* buf, size_t len, int timeoutMs, const Error& ec, size_t totalDone, H&& h)
	{
		SPAS_ASSERT(totalDone <= len);
		if (ec || totalDone==len)
		{
			h(ec, totalDone);
			return;
		}

		sock.asyncSendSome(buf+totalDone, len-totalDone, timeoutMs,
			[&sock,buf,len,timeoutMs,totalDone,h=std::move(h)](const Error& ec, size_t transfered) mutable
		{
			asyncSendHelper(sock, buf, len, timeoutMs, ec, totalDone + transfered, h);
		});
	}

	template< typename H, typename = detail::IsTransferHandler<H> >
	void asyncReceiveHelper(Socket& sock, char* buf, size_t len, int timeoutMs, const Error& ec, size_t totalDone, H&& h)
	{
		SPAS_ASSERT(totalDone <= len);
		if (ec || totalDone==len)
		{
			h(ec, totalDone);
			return;
		}

		sock.asyncReceiveSome(buf+totalDone, len-totalDone, timeoutMs,
			[&sock,buf,len,timeoutMs,totalDone,h=std::move(h)](const Error& ec, size_t transfered) mutable
		{
			asyncReceiveHelper(sock, buf, len, timeoutMs, ec, totalDone + transfered, h);
		});
	}
}

template< typename H, typename = detail::IsTransferHandler<H> >
void asyncSend(Socket& sock, const char* buf, size_t len, int timeoutMs, H&& h)
{
	asyncSendHelper(sock, buf, len, timeoutMs, Error(), 0, std::forward<H>(h));
}

template< typename H, typename = detail::IsTransferHandler<H> >
void asyncReceive(Socket& sock, char* buf, size_t len, int timeoutMs, H&& h)
{
	asyncReceiveHelper(sock, buf, len, timeoutMs, Error(), 0, std::forward<H>(h));
}

} // namespace spas
} // namespace cz
