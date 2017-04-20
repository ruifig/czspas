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


namespace detail
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

		template<typename T>
		void push(T&& item) {
			std::lock_guard<std::mutex> lock(m_mtx);
			m_queue.push(std::forward<T>(item));
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

	// #TODO : Are these needed?
	template<typename H>
	using IsTransferHandler = std::enable_if_t<check_signature<H, void(const Error&, int)>::value>;
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
				auto ec = detail::ErrorWrapper().getError();
				closeSocket(s);
				return std::make_pair(ec, CZSPAS_INVALID_SOCKET);
			}

			// Enable any loopback optimizations (in case this socket is used in a loopback)
			detail::utils::optimizeLoopback(s);

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
				return std::make_pair(Error(Error::Code::Cancelled), CZSPAS_INVALID_SOCKET);
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

	/*
	Same as std::find_if, but uses the full container range.
	*/
	template<typename C, typename F>
	auto find_if(C& c, const F& f) -> decltype(c.begin())
	{
		return std::find_if(c.begin(), c.end(), f);
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

	// 
	// Runs a poll()/WSAPoll() on a different thread, and calls registered handlers whenever there is a event available.
	//
	class IODemux
	{
	public:
		using EventHandler = void(*)(bool cancelled, void* cookie);

		enum class Reason
		{
			Ok,
			Cancel,
			Timeout,
			Disconnect,
			Error
		};

		IODemux()
		{
			auto acceptor = utils::createListenSocket(0, 1);
			CZSPAS_ASSERT(!acceptor.first);

			auto connectFt = std::async(std::launch::async, [this, port=detail::utils::getLocalAddr(acceptor.second).second]
			{
				auto res = detail::utils::createConnectSocket("127.0.0.1", port);
				CZSPAS_ASSERT(!res.first);
				return res.second;
			});

			auto res = detail::utils::accept(acceptor.second);
			detail::utils::closeSocket(acceptor.second);
			CZSPAS_ASSERT(!res.first);
			m_signalIn = res.second;
			m_signalOut = connectFt.get();

			// We reserve index 0 for the signalIn socket. This never gets changed or removed
			m_sockets.get(m_signalIn, POLLRDNORM);

			m_th = std::thread([this] {
				run();
			});
		}

		~IODemux()
		{
			m_finish = true;
			signal();
			m_th.join();
			detail::utils::closeSocket(m_signalOut);
			detail::utils::closeSocket(m_signalIn);
		}

		void registerReceive(SocketHandle s, EventHandler h, void* cookie, int timeoutMs = -1)
		{
			m_newOps([&](auto& q)
			{
				q.push({ s, h, cookie, POLLRDNORM, timeoutMs });
			});
			signal();
		}

		void registerSend(SocketHandle s, EventHandler h, void* cookie, int timeoutMs = -1)
		{
			m_newOps([&](auto& q)
			{
				q.push({ s, h, cookie, POLLWRNORM, timeoutMs});
			});
			signal();
		}

		void cancelRequests(SocketHandle s)
		{
			m_newOps([&](auto& q)
			{
				q.push({ s, nullptr, nullptr, 0, -1});
			});
			signal();
		}

	private:

#if _WIN32
		detail::WSAInstance m_wsaInstance;
#endif
		using TimePoint = std::chrono::time_point<std::chrono::high_resolution_clock>;

		struct NewOp
		{
			SocketHandle fd;
			EventHandler evtHandler;
			void* cookie;
			short flag; // POLLRDNORM, POLLWRNORM, or 0 (cancel)
			int timeoutMs;
		};

		struct Handler
		{
			EventHandler evtHandler = nullptr;
			void* cookie = nullptr;
			TimePoint timeoutPoint;
		};

		struct Set
		{
			std::pair<pollfd*, Handler*> getAt(int idx , short flag)
			{
				CZSPAS_ASSERT(flag == POLLWRNORM || flag == POLLRDNORM);
				CZSPAS_ASSERT(idx < static_cast<int>(fds.size()) && handlers.size() == fds.size() * 2);
				return std::make_pair(&fds[idx], &handlers[idx * 2 + (flag == POLLRDNORM ? 0 : 1)]);
			}

			std::pair<pollfd*, Handler*> get(SocketHandle fd, short flag)
			{
				CZSPAS_ASSERT(flag == POLLWRNORM || flag == POLLRDNORM);
				size_t idx;
				for (idx = 0; idx < fds.size(); idx++)
				{
					if (fds[idx].fd == fd)
						break;
				}

				if (idx == fds.size())
				{
					fds.push_back({ fd, flag , 0 });
					handlers.emplace_back();
					handlers.emplace_back();
				}

				return getAt(static_cast<int>(idx), flag);
			}
			
			void remove(int idx)
			{
				CZSPAS_ASSERT(idx < static_cast<int>(fds.size()) && handlers.size() == fds.size() * 2);
				detail::removeAndReplaceWithLast(fds, fds.begin() + idx);
				// #TODO : Replace this with something that removes 2 elements in one go
				detail::removeAndReplaceWithLast(handlers, handlers.begin() + idx * 2 + 1);
				detail::removeAndReplaceWithLast(handlers, handlers.begin() + idx * 2);
			}

			// These two vector have the following relation:
			// For a given element at index I in m_fds, there are two entries in m_handlers (at indexes I*2 and I*2+1)
			std::vector<pollfd> fds;
			std::vector<Handler> handlers;
		};

		detail::Monitor<std::queue<NewOp>> m_newOps;
		Set m_sockets;
		std::thread m_th;
		SocketHandle m_signalIn;
		SocketHandle m_signalOut;
		bool m_finish = false;

		// Sends data to signal socket, to cause poll to break
		void signal()
		{
			char buf = 0;
			if (::send(m_signalOut, &buf, 1, 0) != 1)
				CZSPAS_FATAL("IODemux %p", this, detail::ErrorWrapper().msg().c_str());
		}

		// Read as much data as possible from the signalIn socket
		void readSignalIn()
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
						CZSPAS_FATAL("IODemux %p: %s", this, err.msg().c_str());
					}
				}
			}
		}

		std::queue<NewOp> m_tmpOps;

		void setEventHandler(const NewOp& op)
		{
			auto f = m_sockets.get(op.fd, op.flag);
			f.first->events |= op.flag;
			CZSPAS_ASSERT(f.second->evtHandler == nullptr);
			f.second->evtHandler = op.evtHandler;
			f.second->cookie = op.cookie;
			if (op.timeoutMs == -1)
				f.second->timeoutPoint = TimePoint::max();
			else
				f.second->timeoutPoint = std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(op.timeoutMs);
		}

		void handleEvent(int idx, short flag)
		{
			auto f = m_sockets.getAt(idx, flag);
			if (f.first->revents & flag)
			{
				// We handle 1 single event of this type, so disable the request for this type of event
				f.first->events &= ~flag; 
				f.second->evtHandler(false, f.second->cookie);
				f.second->evtHandler = nullptr;
				f.second->cookie = nullptr;
			}
		}

		void cancelEvent(int idx, short flag, Reason reason)
		{
			// #TODO : Pass the reason to the handler somehow

			auto f = m_sockets.getAt(idx, flag);
			if (f.first->events & flag)
			{
				// We handle 1 single event of this type, so disable the request for this type of event
				f.first->events &= ~flag; 
				f.second->evtHandler(true, f.second->cookie);
				f.second->evtHandler = nullptr;
				f.second->cookie = nullptr;
			}
		}

		void checkTimeouts()
		{
			auto now = std::chrono::high_resolution_clock::now();
			for (int idx = 1; idx < static_cast<int>(m_sockets.fds.size());)
			{
				// #TODO : Improve this by possibly iterating the 2 handler entries?
				auto f = m_sockets.getAt(idx, POLLRDNORM);
				if (f.second->evtHandler && now > f.second->timeoutPoint)
				{
					cancelEvent(idx, POLLRDNORM, Reason::Timeout);
				}
				f = m_sockets.getAt(idx, POLLWRNORM);
				if (f.second->evtHandler && now > f.second->timeoutPoint)
				{
					cancelEvent(idx, POLLWRNORM, Reason::Timeout);
				}

				// If we are not interested in any more request from this handler, remove it
				if ((f.first->events & (POLLRDNORM | POLLWRNORM)) == 0)
				{
					m_sockets.remove(idx);
				}
				else
				{
					++idx;
				}
			}
		}

		void run()
		{
			TimePoint timeoutPoint = TimePoint::max();
			while (!m_finish)
			{

				// 
				// Calculate the timeout we need for the poll()
				for (auto&& h : m_sockets.handlers)
				{
					if (h.evtHandler && h.timeoutPoint < timeoutPoint)
						timeoutPoint = h.timeoutPoint;
				}

				int timeoutMs = -1;
				if (timeoutPoint != TimePoint::max())
					timeoutMs = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(timeoutPoint - std::chrono::high_resolution_clock::now()).count());

				auto res = WSAPoll(&m_sockets.fds.front(), static_cast<unsigned long>(m_sockets.fds.size()), timeoutMs);
				if (res == 0) // Timeout
				{
					checkTimeouts();
				}
				else if (res == CZSPAS_SOCKET_ERROR)
				{
					CZSPAS_FATAL("IODemux %p: %s", this, detail::ErrorWrapper().msg().c_str());
				}
				// else if (res>0) // Number of elements in the fds array for which an revents nember is nonzero

				if (m_sockets.fds[0].revents & POLLRDNORM)
				{
					readSignalIn();
				}

				//
				// Process received events
				//
				for (int idx = 1; idx < static_cast<int>(m_sockets.fds.size()); )
				{
					auto&& f = m_sockets.fds[idx];
					if (f.revents & (POLLERR | POLLHUP | POLLNVAL))
					{
						cancelEvent(idx, POLLRDNORM, (f.revents & POLLHUP) ? Reason::Disconnect : Reason::Error);
						cancelEvent(idx, POLLWRNORM, (f.revents & POLLHUP) ? Reason::Disconnect : Reason::Error);
					}
					else
					{
						handleEvent(idx, POLLRDNORM);
						handleEvent(idx, POLLWRNORM);
					}

					// If we are not interested in any more request from this handler, remove it
					if ((f.events & (POLLRDNORM | POLLWRNORM)) == 0)
					{
						m_sockets.remove(idx);
					}
					else
					{
						++idx;
					}
				}

				//
				// Process new operations
				//
				m_newOps([&](auto& q)
				{
					std::swap(q, m_tmpOps);
				});

				while (m_tmpOps.size())
				{
					NewOp op = m_tmpOps.front();
					m_tmpOps.pop();
					if (op.flag == 0) // 0 means Cancel
					{
						// If the handler is not found, we don't need to do anything
						for (int idx = 1; idx < static_cast<int>(m_sockets.fds.size()); ++idx)
						{
							if (m_sockets.fds[idx].fd == op.fd)
							{
								cancelEvent(idx, POLLRDNORM, Reason::Cancel);
								cancelEvent(idx, POLLWRNORM, Reason::Cancel);
								m_sockets.remove(idx);
							}
						}
					}
					else
					{
						setEventHandler(op);
					}
				}

			}
		}

	};

	class BaseService;

	//////////////////////////////////////////////////////////////////////////
	// BaseSocket
	//////////////////////////////////////////////////////////////////////////
	class BaseSocket
	{
	public:
		BaseSocket(detail::BaseService& owner) : m_owner(owner) {}
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
		friend Service;
		bool isValid() const
		{
			return m_s != CZSPAS_INVALID_SOCKET;
		}

		void releaseHandle()
		{
			detail::utils::closeSocket(m_s);
			m_s = CZSPAS_INVALID_SOCKET;
		}

		detail::BaseService& m_owner;
		SocketHandle m_s = CZSPAS_INVALID_SOCKET;
	};

	// This is not part of the Service class, so that we can break the circular dependency
	// between Acceptor/Socket and Service
	class BaseService
	{
	public:
		BaseService()
		{
		}

	protected:
		IODemux m_iodemux;
		using ReadyQueue = std::queue<std::function<void()>>;

		friend class cz::spas::Socket;
		friend class cz::spas::Acceptor;

		template< typename H, typename = IsSimpleHandler<H> >
		void queueReadyHandler(H&& h)
		{
			m_readyHandlers.push(std::forward<H>(h));
		}

		SharedQueue<std::function<void()>> m_readyHandlers;
	};

} // namespace detail

//////////////////////////////////////////////////////////////////////////
// Socket
//////////////////////////////////////////////////////////////////////////
class Socket : public detail::BaseSocket
{
public:

	Socket(detail::BaseService& service)
		: detail::BaseSocket(service)
	{
	}

	virtual ~Socket()
	{
		CZSPAS_ASSERT(m_connect.handler == nullptr && "There is a pending connect operation");
		CZSPAS_ASSERT(m_recv.handler == nullptr && "There is a pending receive operation");
		CZSPAS_ASSERT(m_send.handler == nullptr && "There is a pending send operation");
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

		m_localAddr = detail::utils::getLocalAddr(m_s);
		m_peerAddr = detail::utils::getRemoteAddr(m_s);
		CZSPAS_INFO("Socket %p: Connected to %s:%d", this, m_peerAddr.first.c_str(), m_peerAddr.second);

		return Error();
	}
	 
	// #TODO : Remove the timeout parameter, and assume a default
	// 
	void asyncConnect(const char* ip, int port, int timeoutMs, ConnectHandler h)
	{
		CZSPAS_ASSERT(!isValid());
		CZSPAS_INFO("Socket %p: asyncConnect(%s,%d, H, %d)", this, ip, port, timeoutMs);

		m_connect.handler = std::move(h);
		m_s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (m_s == CZSPAS_INVALID_SOCKET)
		{
			auto ec = detail::ErrorWrapper().getError();
			CZSPAS_ERROR("Socket %p: %s", this, ec.msg());
			m_owner.queueReadyHandler([this, ec = std::move(ec)]
			{
				auto data = m_connect.moveAndClear();
				data.handler(ec);
			});
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

		if (::connect(m_s, (const sockaddr*)&addr, sizeof(addr)) == CZSPAS_SOCKET_ERROR)
		{
			detail::ErrorWrapper err;
			if (err.isBlockError())
			{
				// Normal behavior, so setup the connect detection with select
				// A asynchronous connect is done when we receive a write event on the socket
				m_owner.m_iodemux.registerSend(m_s, &handleConnect, this, timeoutMs);
			}
			else
			{
				// #TODO : Do a unit test to cover this code path
				m_owner.queueReadyHandler([this, ec = err.getError()]
				{
					auto data = m_connect.moveAndClear();
					data.handler(ec);
				});
			}
		}
		else
		{
			// It may happen that the connect succeeds right away.
			m_owner.queueReadyHandler([this]
			{
				auto data = m_connect.moveAndClear();
				data.handler(Error());
			});
		}
	}

	template< typename H, typename = detail::IsTransferHandler<H> >
	void asyncReceiveSome(char* buf, int len, int timeoutMs, H&& h)
	{
		CZSPAS_ASSERT(isValid());
		CZSPAS_ASSERT(!m_recv.handler); // There can be only one receive operation in flight
		m_recv.buf = buf;
		m_recv.len = len;
		m_recv.handler = std::move(h);
		m_owner.m_iodemux.registerReceive(m_s, &handleReceive, this, timeoutMs);
	}
	template< typename H, typename = detail::IsTransferHandler<H> >
	void asyncSendSome(const char* buf, int len, int timeoutMs, H&& h)
	{
		CZSPAS_ASSERT(!m_sendHandler); // There can be only one send operation in flight
		m_send.buf = buf;
		m_send.len = len;
		m_send.handler = std::move(h);
		m_owner.m_iodemux.registerSend(m_s, &handleSend, this, timeoutMs);
	}

	void close()
	{
		// #TODO : Implement this ???
	}

	void cancel()
	{
		if (m_connect.handler || m_recv.handler || m_send.handler)
			m_owner.m_iodemux.cancelRequests(m_s);
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

	static void handleReceive(bool cancelled, void* cookie)
	{
		reinterpret_cast<Socket*>(cookie)->handleReceiveImpl(cancelled);
	}
	void handleReceiveImpl(bool cancelled)
	{
		CZSPAS_ASSERT(m_recv.handler);

		int len = ::recv(m_s, m_recv.buf, m_recv.len, 0);
		if (len == CZSPAS_SOCKET_ERROR)
		{
			detail::ErrorWrapper err;
			if (cancelled)
			{
				m_owner.queueReadyHandler([this, ec=err.getError()]
				{
					auto data = m_recv.moveAndClear();
					data.handler(Error(Error::Code::Cancelled), 0);
				});
			}
			else if (err.isBlockError())
			{
				CZSPAS_FATAL("Blocking not expected at this point.");
			}
			else
			{
				CZSPAS_ERROR(err.msg().c_str());
				m_owner.queueReadyHandler([this, ec=err.getError()]
				{
					auto data = m_recv.moveAndClear();
					data.handler(ec, 0);
				});
			}
		}
		else
		{
			m_owner.queueReadyHandler([this, len, cancelled]
			{
				auto data = m_recv.moveAndClear();
				data.handler(Error(cancelled ? Error::Code::Cancelled : Error::Code::Success), len);
			});
		}
	}

	static void handleSend(bool cancelled, void* cookie)
	{
		reinterpret_cast<Socket*>(cookie)->handleReceiveImpl(cancelled);
	}
	void handleSendImpl(bool cancelled)
	{
		// #TODO : Fill me
	}

	static void handleConnect(bool cancelled, void* cookie)
	{
		reinterpret_cast<Socket*>(cookie)->handleConnectImpl(cancelled);
	}
	void handleConnectImpl(bool cancelled)
	{
		CZSPAS_ASSERT(m_connect.handler);
		m_owner.queueReadyHandler([this, cancelled]
		{
			auto data = m_connect.moveAndClear();
			data.handler(Error(cancelled ? Error::Code::Cancelled : Error::Code::Success));
		});
	}

	friend Acceptor;
	std::pair<std::string, int> m_localAddr;
	std::pair<std::string, int> m_peerAddr;

	struct ConnectData
	{
		ConnectHandler handler;
		ConnectData moveAndClear()
		{
			ConnectData res = std::move(*this);
			handler = nullptr;
			return res;
		}
	} m_connect;

	struct ReceiveData
	{
		char* buf = nullptr;
		int len = 0;
		TransferHandler handler;
		ReceiveData moveAndClear()
		{
			ReceiveData res = std::move(*this);
			buf = nullptr;
			len = 0;
			handler = nullptr;
			return res;
		}
	} m_recv;

	struct SendData
	{
		const char* buf = nullptr;
		int len = 0;
		TransferHandler handler;
		SendData moveAndClear()
		{
			SendData res = std::move(*this);
			buf = nullptr;
			len = 0;
			handler = nullptr;
			return res;
		}
	} m_send;
};

//////////////////////////////////////////////////////////////////////////
// Acceptor
//////////////////////////////////////////////////////////////////////////
class Acceptor : public detail::BaseSocket
{
public:

	Acceptor(detail::BaseService& service)
		: detail::BaseSocket(service)
	{
	}

	virtual ~Acceptor()
	{
		CZSPAS_ASSERT(m_accept.handler==nullptr && "There is a pending accept operation");
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

		m_localAddr = detail::utils::getLocalAddr(m_s);
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

		sock.m_localAddr = detail::utils::getLocalAddr(sock.m_s);
		sock.m_peerAddr = detail::utils::getRemoteAddr(sock.m_s);
		CZSPAS_INFO("Acceptor %p: Socket %p connected to %s:%d", this, &sock, sock.m_peerAddr.first.c_str(),
		            sock.m_peerAddr.second);

		// No error
		return Error();
	}

	template< typename H, typename = detail::IsAcceptHandler<H> >
	void asyncAccept(Socket& sock, int timeoutMs, H&& h)
	{
		CZSPAS_ASSERT(isValid());
		CZSPAS_ASSERT(!m_accept.handler && "There is already a pending accept operation");
		CZSPAS_ASSERT(!sock.isValid());

		m_accept.handler = std::move(h);
		m_accept.sock = &sock;
		m_owner.m_iodemux.registerReceive(m_s, &handleAccept, this, timeoutMs);
	}

	void close()
	{
		// #TODO : Fill me
	}

	void cancel()
	{
		if (m_accept.handler)
			m_owner.m_iodemux.cancelRequests(m_s);
	}

	const std::pair<std::string, int>& getLocalAddress() const
	{
		return m_localAddr;
	}

protected:

	static void handleAccept(bool cancelled, void* cookie)
	{
		reinterpret_cast<Acceptor*>(cookie)->handleAcceptImpl(cancelled);
	}
	void handleAcceptImpl(bool cancelled)
	{
		CZSPAS_ASSERT(m_accept.handler);
		CZSPAS_ASSERT(m_accept.sock && !m_accept.sock->isValid());

		if (cancelled)
		{
			m_owner.queueReadyHandler([this]
			{
				auto data = m_accept.moveAndClear();
				data.handler(Error(Error::Code::Cancelled));
			});
		}
		else
		{
			sockaddr_in addr;
			socklen_t size = sizeof(addr);
			SocketHandle sock = ::accept(m_s, (struct sockaddr*)&addr, &size);
			m_owner.queueReadyHandler([this, sock]
			{
				auto data = m_accept.moveAndClear();
				data.sock->m_s = sock;
				if (data.sock->m_s == CZSPAS_INVALID_SOCKET)
				{
					data.handler(detail::ErrorWrapper().getError());
				}
				else
				{
					detail::utils::setBlocking(data.sock->m_s, false);
					data.handler(Error());
				}
			});
		}
	}

	std::pair<std::string, int> m_localAddr;
	struct AcceptData
	{
		AcceptHandler handler = nullptr;
		Socket* sock = nullptr;
		AcceptData moveAndClear()
		{
			AcceptData res = std::move(*this);
			handler = nullptr;
			sock = nullptr;
			return res;
		}
	} m_accept;
};


//////////////////////////////////////////////////////////////////////////
// Service
//////////////////////////////////////////////////////////////////////////
class Service : public detail::BaseService
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
	bool tick(bool block = false)
	{
		CZSPAS_ASSERT(m_tmpQ.size() == 0);
		m_readyHandlers.swap(m_tmpQ, block);
		while (m_tmpQ.size())
		{
			m_tmpQ.front()();
			m_tmpQ.pop();
		}
		return !m_finish;
	}

	// Continuously wait for and executes handlers.
	// Only returns when a "stop" is called
	void run()
	{
		while (tick(true))
		{
		}
	}

	//! Causes the Service to be signaled as finished, and thus causing "run" to return false
	void stop()
	{
		m_readyHandlers.push([this]()
		{
			m_finish = true;
		});
	}

	// Request to invoke the specified handler
	// The handler is NOT called from inside this function.
	template< typename H, typename = detail::IsSimpleHandler<H> >
	void post(H&& handler)
	{
		m_readyHandlers.push(std::forward<H>(handler));
	}

	// Request to invoke the specified handler
	// The handler can be invoked from inside this function (if the current thread is executing tick)
	template< typename H, typename = detail::IsSimpleHandler<H> >
	void dispatch(H&& handler)
	{
		// #TODO : Fill me
	}

protected:
	std::queue<std::function<void()>> m_tmpQ;
	bool m_finish = false;
};

} // namespace spas
} // namespace cz
