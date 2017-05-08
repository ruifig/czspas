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
	#define CZSPAS_DEBUG_BREAK __debugbreak
#else
	#define CZSPAS_DEBUG_BREAK __builtin_trap
#endif

namespace cz
{
namespace spas
{

// Forward declarations
class Acceptor;
class Socket;
class Service;

#ifndef CZSPAS_INFO
	#define CZSPAS_INFO(fmt, ...) detail::DefaultLog::out(false, "Info: ", fmt, ##__VA_ARGS__)
#endif
#ifndef CZSPAS_WARN
	#define CZSPAS_WARN(fmt, ...) detail::DefaultLog::out(false, "Warning: ", fmt, ##__VA_ARGS__)
#endif
#ifndef CZSPAS_ERROR
	#define CZSPAS_ERROR(fmt, ...) detail::DefaultLog::out(false, "Error: ", fmt, ##__VA_ARGS__)
#endif
#ifndef CZSPAS_FATAL
	#define CZSPAS_FATAL(fmt, ...) detail::DefaultLog::out(true, "Fatal: ", fmt, ##__VA_ARGS__)
#endif

#ifndef CZSPAS_ASSERT
	#define CZSPAS_ASSERT(expr) \
		if (!(expr)) CZSPAS_FATAL(#expr)
#endif

#if _WIN32
	using SocketHandle = SOCKET;
	#define CZSPAS_INVALID_SOCKET INVALID_SOCKET
	#define CZSPAS_SOCKET_ERROR SOCKET_ERROR
#else
	using SocketHandle = int;
	#define CZSPAS_INVALID_SOCKET -1
	#define CZSPAS_SOCKET_ERROR -1
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
				CZSPAS_DEBUG_BREAK();
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

	//
	// Multiple producer, multiple consumer thread safe queue
	//
	template<typename T>
	class SharedQueue
	{
	private:
		std::queue<T> m_queue;
		mutable std::mutex m_mtx;
		std::condition_variable m_data_cond;

		SharedQueue& operator=(const SharedQueue&) = delete;
		SharedQueue(const SharedQueue& other) = delete;

	public:
		SharedQueue() {}

		// #TODO : Remove this. Was just for debugging
		int _getSize() const
		{
			return (int)m_queue.size();
		}

		template<typename Item>
		void push(Item&& item) {
			std::lock_guard<std::mutex> lock(m_mtx);
			m_queue.push(std::forward<Item>(item));
			m_data_cond.notify_one();
		}

		//! swaps the contents of the internal queue by the supplied queue
		// This allows the caller to process a batch of items without making repeated calls to the SharedQueue
		// \param q
		//		Queue to swap with	
		// \param block
		//		If true, it will block waiting for items to arrive at the internal queue
		// \return
		//		New size of the supplied queue
		size_t swap(std::queue<T>& q, bool block)
		{
			std::unique_lock<std::mutex> lock(m_mtx);
			if (block)
				m_data_cond.wait(lock, [this] { return !m_queue.empty(); });
			std::swap(q, m_queue);
			// If we had no items and now have some, notify
			if (m_queue.size()>1 && q.size()==0)
				m_data_cond.notify_one();
			return q.size();
		}
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

		static void closeSocket(SocketHandle& s, bool doshutdown=true)
		{
			if (s == CZSPAS_INVALID_SOCKET)
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
				CZSPAS_FATAL(ErrorWrapper().msg().c_str());
		}

		static void setReuseAddress(SocketHandle s)
		{
			int optval = 1;
			int res = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&optval, sizeof(optval));
			if (res != 0)
				CZSPAS_FATAL(ErrorWrapper().msg().c_str());
		}

		// Set the linger option, in seconds
		static void setLinger(SocketHandle s, bool enabled, u_short timeout)
		{
			linger l;
			l.l_onoff = enabled ? 1 : 0;
			l.l_linger = timeout;
			int res = setsockopt(s, SOL_SOCKET, SO_LINGER, (const char*)&l, sizeof(l));
			if (res != 0)
				CZSPAS_FATAL(ErrorWrapper().msg().c_str());
		}

#if 0
		static int getSendBufSize(SocketHandle s)
		{
			int sndbuf;
			socklen_t optlen = sizeof(sndbuf);
			auto res = getsockopt(s, SOL_SOCKET, SO_SNDBUF, (char*)&sndbuf, &optlen);
			if (res != 0)
				CZSPAS_FATAL(ErrorWrapper().msg().c_str());
			return sndbuf;
		}

		static void setSendBufSize(SocketHandle s, int size)
		{
			auto res = setsockopt(s, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
			if (res != 0)
				CZSPAS_FATAL(ErrorWrapper().msg().c_str());
		}

		static int getReceiveBufSize(SocketHandle s)
		{
			int sndbuf;
			socklen_t optlen = sizeof(sndbuf);
			auto res = getsockopt(s, SOL_SOCKET, SO_RCVBUF, (char*)&sndbuf, &optlen);
			if (res != 0)
				CZSPAS_FATAL(ErrorWrapper().msg().c_str());
			return sndbuf;
		}
#endif

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
				//CZSPAS_FATAL(ErrorWrapper().msg().c_str());
				return std::make_pair("", 0);
			}
		}

		//! Creates a socket and puts it into listen mode
		//
		// \param port
		//		What port to listen on. If 0, the OS will pick a port from the dynamic range
		// \param ec
		//		If an error occurs, this contains the error.
		// \param backlog
		//		Size of the the connection backlog.
		//		Also, this is only an hint to the OS. It's not guaranteed.
		//
		static std::pair<Error, SocketHandle> createListenSocket(int port, int backlog)
		{
			SocketHandle s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			printf("createListenSocket(%d,%d) : %d\n", port, backlog, (int)s);
			if (s == CZSPAS_INVALID_SOCKET)
				return std::make_pair(detail::ErrorWrapper().getError(), s);

			detail::utils::setReuseAddress(s);

			sockaddr_in addr;
			addr.sin_family = AF_INET;
			addr.sin_port = htons(port);
			addr.sin_addr.s_addr = htonl(INADDR_ANY);
			if (
				(::bind(s, (const sockaddr*)&addr, sizeof(addr)) == CZSPAS_SOCKET_ERROR) ||
				(::listen(s, backlog) == CZSPAS_SOCKET_ERROR)
				)
			{
				printf("createListenSocket(%d,%d) :  %d error\n", port, backlog, (int)s);
				auto ec = detail::ErrorWrapper().getError();
				closeSocket(s);
				return std::make_pair(ec, CZSPAS_INVALID_SOCKET);
			}

			// Enable any loopback optimizations (in case this socket is used in a loopback)
			detail::utils::optimizeLoopback(s);

			printf("createListenSocket(%d,%d) : %d ok\n", port, backlog, (int)s);
			return std::make_pair(Error(), s);
		}

		//! Synchronous connect
		static std::pair<Error, SocketHandle> createConnectSocket(const char* ip, int port)
		{
			SocketHandle s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (s == CZSPAS_INVALID_SOCKET)
				return std::make_pair(detail::ErrorWrapper().getError(), s);

			// Enable any loopback optimizations (in case this socket is used in loopback)
			detail::utils::optimizeLoopback(s);

			sockaddr_in addr;
			memset(&addr, 0, sizeof(addr));
			addr.sin_family = AF_INET;
			addr.sin_port = htons(port);
			inet_pton(AF_INET, ip, &(addr.sin_addr));
			if (::connect(s, (const sockaddr*)&addr, sizeof(addr)) == CZSPAS_SOCKET_ERROR)
			{
				auto ec = detail::ErrorWrapper().getError();
				closeSocket(s);
				return std::make_pair(ec, CZSPAS_INVALID_SOCKET);
			}

			detail::utils::setBlocking(s, false);
			return std::make_pair(Error(), s);
		}

		static std::pair<Error, SocketHandle> accept(SocketHandle& acceptor, int timeoutMs = -1)
		{
			CZSPAS_ASSERT(acceptor != CZSPAS_INVALID_SOCKET);

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

			if (res == CZSPAS_SOCKET_ERROR) {
				return std::make_pair(detail::ErrorWrapper().getError(), CZSPAS_INVALID_SOCKET);
			}
			else if (res == 0) {
				return std::make_pair(Error(Error::Code::Timeout), CZSPAS_INVALID_SOCKET);
			}

			CZSPAS_ASSERT(res == 1);
			CZSPAS_ASSERT(FD_ISSET(acceptor, &fds));

			sockaddr_in addr;
			socklen_t size = sizeof(addr);
			SocketHandle s = ::accept(acceptor, (struct sockaddr*)&addr, &size);
			if (s == CZSPAS_INVALID_SOCKET)
				return std::make_pair(detail::ErrorWrapper().getError(), s);

			detail::utils::setBlocking(s, false);

			return std::make_pair(Error(), s);
		}

	};

	template <class T, class MTX=std::mutex>
	class Monitor
	{
	private:
		mutable T m_t;
		mutable MTX m_mtx;

	public:
		using Type = T;
		Monitor() {}
		Monitor(T t_) : m_t(std::move(t_)) {}
		template <typename F>
		auto operator()(F f) const -> decltype(f(m_t))
		{
			std::lock_guard<std::mutex> hold{ m_mtx };
			return f(m_t);
		}
	};

	template<typename T>
	typename std::vector<T>::iterator removeAndReplaceWithLast(std::vector<T>& c, typename std::vector<T>::iterator it)
	{
		assert(it != c.end());
		if (it == c.end() - 1)
		{
			return c.erase(it);
		}
		else
		{
			*it = std::move(*(c.end() - 1));
			c.erase(c.cend() - 1);
			return it;
		}
	}

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

	struct AcceptOperation;
	struct ConnectOperation;

	class BaseService
	{
	};

	class BaseSocket
	{
	public:
		BaseSocket(detail::BaseService& owner)
			: m_owner(owner)
			, m_pendingOps(0)
		{
		}
		virtual ~BaseSocket()
		{
			CZSPAS_ASSERT(m_pendingOps.load() == 0);
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

	protected:
		BaseSocket(const BaseSocket&) = delete;
		void operator=(const BaseSocket&) = delete;

		friend AcceptOperation;
		friend ConnectOperation;
		friend Acceptor;
		bool isValid() const
		{
			return m_s != CZSPAS_INVALID_SOCKET;
		}

		void resolveAddrs()
		{
			m_localAddr = detail::utils::getLocalAddr(m_s);
			m_peerAddr = detail::utils::getRemoteAddr(m_s);
		}

		detail::BaseService& m_owner;
		SocketHandle m_s = CZSPAS_INVALID_SOCKET;
		std::atomic<int> m_pendingOps; // Only for debugging: #TODO : Add a define to have it available only on Debug build
		std::pair<std::string, int> m_localAddr;
		std::pair<std::string, int> m_peerAddr;
	};

	struct Operation
	{
		Error ec;
		virtual ~Operation() { }
		virtual void exec(SocketHandle fd) = 0;
		virtual void callUserHandler() = 0;
	};

	struct PostOperation : Operation
	{
		std::function<void()> userHandler;
		template<typename H>
		PostOperation(H&& h)
			: userHandler(std::forward<H>(h)) {}
		virtual void exec(SocketHandle fd) override {}
		virtual void callUserHandler() { userHandler(); }
	};

	struct SocketOperation : public Operation
	{
		BaseSocket& owner;
		explicit SocketOperation(BaseSocket& owner) : owner(owner) {}
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
		}

		virtual void exec(SocketHandle fd) override
		{
			sockaddr_in addr;
			socklen_t size = sizeof(addr);
			sock.m_s = ::accept(fd, (struct sockaddr*)&addr, &size);
			if (sock.m_s == CZSPAS_INVALID_SOCKET)
				ec = detail::ErrorWrapper().getError();
			else
			{
				detail::utils::setBlocking(sock.m_s, false);
				sock.resolveAddrs();
			}
		}

		virtual void callUserHandler() override
		{
			--owner.m_pendingOps;
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
		}

		virtual void exec(SocketHandle fd) override
		{
			CZSPAS_ASSERT(fd == owner.getHandle());
			owner.resolveAddrs();
		}

		virtual void callUserHandler() override
		{
			--owner.m_pendingOps;
			userHandler(ec);
		}
	};

	struct TransferOperation : public SocketOperation
	{
		char* buf;
		size_t bufSize;
		size_t transfered = 0;
		std::function<void(const Error& ec, size_t transfered)> userHandler;
	};

	struct SendOperation : public TransferOperation
	{
	};

	struct ReceiveOperation : public TransferOperation
	{
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
	bool processEventsHelper(SocketHandle fd, OperationData& opdata, int ready, Timepoint expirePoint,
	                         std::queue<std::unique_ptr<Operation>>& dst)
	{
		if (!opdata.op)
			return true;

		if (ready)
		{
			opdata.op->exec(fd);
			dst.push(std::move(opdata.op));
			return true;
		}
		else if (opdata.timeout < expirePoint)
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
			if (fd.revents & (POLLERR | POLLHUP | POLLNVAL))
			{
				it->second.cancel((fd.revents & POLLHUP) ? Error::Code::ConnectionClosed : Error::Code::InvalidSocket, dst);
				m_sockData.erase(it);
			}
			else
			{
				bool empty =
				    processEventsHelper(it->first, it->second.ops[EventType::Read], fd.revents & POLLRDNORM, now, dst);
				empty = empty && processEventsHelper(it->first, it->second.ops[EventType::Write],
				                                     fd.revents & POLLWRNORM, now, dst);
				if (empty)
					m_sockData.erase(it);
			}
		}
	}

public:

	Reactor()
	{

		// Create a listening socket on a port picked by the OS (because we passed 0 as port)
		auto acceptor = utils::createListenSocket(0, 1);
		// If this fails, then the OS probably ran out of resources (e.g: Too many connections or too many connection 
		// on TIME_WAIT)
		CZSPAS_ASSERT(!acceptor.first);

		auto connectFt = std::async(std::launch::async, [this, port = detail::utils::getLocalAddr(acceptor.second).second]
		{
			auto res = detail::utils::createConnectSocket("127.0.0.1", port);
			// Same as above. If this fails, then the OS ran out of resources
			CZSPAS_ASSERT(!res.first);
			return res.second;
		});

		auto res = detail::utils::accept(acceptor.second);
		detail::utils::closeSocket(acceptor.second);
		CZSPAS_ASSERT(!res.first);
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
		if (::send(m_signalOut, &buf, 1, 0) != 1)
			CZSPAS_FATAL("Reactor %p", this, detail::ErrorWrapper().msg().c_str());
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
		printf("*\n");
		interrupt();
	}

	/*
	void cancelAll(std::queue<std::unique_ptr<Operation>>& dst)
	{
		std::unique_lock<std::mutex> lk(m_mtx);
		for (auto&& d : m_sockData)
			d.second.cancel(Error::Code::Cancelled, dst);
		m_sockData.clear();
	}
	*/

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
			CZSPAS_ASSERT(m_fds.back().events != 0);
		}

		lk.unlock();

		int timeoutMs = -1;
		if (timeoutPoint != Timepoint::max())
		{
			timeoutMs = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(timeoutPoint - std::chrono::high_resolution_clock::now()).count());
			if (timeoutMs < 0)
				timeoutMs = 0;
		}

		printf("pollBEGIN\n");
#if _WIN32
			auto res = WSAPoll(&m_fds.front(), static_cast<unsigned long>(m_fds.size()), timeoutMs);
#else
			auto res = poll(&m_fds.front(), static_cast<unsigned long>(m_fds.size()), timeoutMs);
#endif
		printf("pollEND\n");

		lk.lock();

		if (m_fds[0].revents & POLLRDNORM)
			readInterrupt();

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
	void post(H&& handler)
	{
		std::lock_guard<std::mutex> lk(m_mtx);
		m_ready.push(std::make_unique<detail::PostOperation>(std::forward<H>(h)));
	}

	void stop()
	{
		m_stopping = true;
		m_reactor.interrupt();
	}

	void run(bool loop=true)
	{
		m_stopping = false;
		while (loop && !m_stopping)
		{
			{
				printf("1\n");
				std::lock_guard<std::mutex> lk(m_mtx);
				std::swap(m_tmpready, m_ready);
			}

			while (m_tmpready.size())
			{
				m_tmpready.front()->callUserHandler();
				m_tmpready.pop();
			}

			printf("2\n");
			m_reactor.runOnce(m_tmpready);
			printf("3\n");

		}
	}

private:

	void cancel(SocketHandle fd)
	{
		std::lock_guard<std::mutex> lk(m_mtx);
		m_reactor.cancel(fd, m_ready);
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
	std::atomic<bool> m_stopping = false;
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

	//! Synchronous connect
	Error connect(const char* ip, int port)
	{
		CZSPAS_ASSERT(!isValid());

		CZSPAS_INFO("Socket %p: Connect(%s,%d)", this, ip, port);
		auto res = detail::utils::createConnectSocket(ip, port);
		if (res.first)
		{
			CZSPAS_ERROR("Socket %p: %s", this, res.first.msg());
			return res.first;
		}
		m_s = res.second;
		resolveAddrs();
		CZSPAS_INFO("Socket %p: Connected to %s:%d", this, m_peerAddr.first.c_str(), m_peerAddr.second);
		return Error();
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
		if (m_s != CZSPAS_INVALID_SOCKET)
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
	Error listen(int port, int backlog)
	{
		CZSPAS_ASSERT(!isValid());
		CZSPAS_INFO("Acceptor %p: listen(%d, %d)", this, port, backlog);

		auto res = detail::utils::createListenSocket(port, backlog);
		if (res.first)
		{
			CZSPAS_ERROR("Acceptor %p: %s", this, res.first.msg());
			return res.first;
		}
		m_s = res.second;

		resolveAddrs();
		// No error
		return Error();
	}

	Error accept(Socket& sock, int timeoutMs = -1)
	{
		CZSPAS_ASSERT(isValid());
		CZSPAS_ASSERT(!sock.isValid());

		auto res = detail::utils::accept(m_s, timeoutMs);
		if (res.first)
		{
			CZSPAS_ERROR("Acceptor %p: %s", this, res.first.msg());
			return res.first;
		}
		sock.m_s = res.second;
		sock.resolveAddrs();
		CZSPAS_INFO("Acceptor %p: Socket %p connected to %s:%d", this, &sock, sock.m_peerAddr.first.c_str(),
		            sock.m_peerAddr.second);

		// No error
		return Error();
	}

	template< typename H, typename = detail::IsAcceptHandler<H> >
	void asyncAccept(Socket& sock, int timeoutMs, H&& h)
	{
		CZSPAS_ASSERT(isValid());
		CZSPAS_ASSERT(!sock.isValid());
		CZSPAS_ASSERT(m_pendingOps.load()==0 && "There is already a pending accept operation");
		auto op = std::make_unique<detail::AcceptOperation>(*this, sock, std::forward<H>(h));
		++m_pendingOps;
		getService().addOperation(m_s, detail::Reactor::EventType::Read, std::move(op), timeoutMs);
	}

	void cancel()
	{
		if (isValid())
			getService().cancel(m_s);
	}

private:

};


} // namespace spas
} // namespace cz
