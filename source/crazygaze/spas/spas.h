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

/*
Random notes/links I use/used during development
------------------------------------------------

Excellent BSD socket tutorial:
	http://beej.us/guide/bgnet/

About compatibility (Windows vs Unix)
	https://tangentsoft.net/wskfaq/articles/bsd-compatibility.html
	https://www.apriorit.com/dev-blog/221-crossplatform-linux-windows-sockets

About socket states:
	http://stackoverflow.com/questions/5328155/preventing-fin-wait2-when-closing-socket

About SO_REUSEADDR / SO_REUSEPORT / SO_LINGER:
	http://stackoverflow.com/questions/14388706/socket-options-so-reuseaddr-and-so-reuseport-how-do-they-differ-do-they-mean-t
	http://stackoverflow.com/questions/3757289/tcp-option-so-linger-zero-when-its-required
	http://www.serverframework.com/asynchronousevents/2011/01/time-wait-and-its-design-implications-for-protocols-and-scalable-servers.html

Windows Loopback fast path:
	https://blogs.technet.microsoft.com/wincat/2012/12/05/fast-tcp-loopback-performance-and-low-latency-with-windows-server-2012-tcp-loopback-fast-path/

Notes on WSAPoll:
	https://blogs.msdn.microsoft.com/wndp/2006/10/26/wsapoll-a-new-winsock-api-to-simplify-porting-poll-applications-to-winsock/
	WSAPoll() is not exactly like poll(). It has a couple of bugs that Microsoft never fixed. Example: 
		- Doesn't report failed connections. (E.g: A connect attempt to an address & port without listener and timeout -1 will block forever):
			https://social.msdn.microsoft.com/Forums/windowsdesktop/en-US/18769abd-fca0-4d3c-9884-1a38ce27ae90/wsapoll-and-nonblocking-connects-to-nonexistent-ports?forum=wsk

*/

#pragma once

#ifdef _WIN32
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
#include <string>
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

#ifdef __GNUG__
	#define __forceinline __attribute__((always_inline)) inline
#endif

namespace cz
{
namespace spas
{

// Forward declarations
class Acceptor;
class Socket;
class Service;

//#define CZSPAS_ENABLE_LOGGING 1

#if CZSPAS_ENABLE_LOGGING
	#ifndef CZSPAS_INFO
		#define CZSPAS_INFO(fmt, ...) ::cz::spas::detail::DefaultLog::out(false, "Info: ", fmt, ##__VA_ARGS__)
	#endif
	#ifndef CZSPAS_WARN
		#define CZSPAS_WARN(fmt, ...) ::cz::spas::detail::DefaultLog::out(false, "Warning: ", fmt, ##__VA_ARGS__)
	#endif
	#ifndef CZSPAS_ERROR
		#define CZSPAS_ERROR(fmt, ...) ::cz::spas::detail::DefaultLog::out(false, "Error: ", fmt, ##__VA_ARGS__)
	#endif
#else
	#ifndef CZSPAS_INFO
		#define CZSPAS_INFO(fmt, ...) ((void)0)
	#endif
	#ifndef CZSPAS_WARN
		#define CZSPAS_WARN(fmt, ...) ((void)0)
	#endif
	#ifndef CZSPAS_ERROR
		#define CZSPAS_ERROR(fmt, ...) ((void)0)
	#endif
#endif

// Fatal logging is always available
#ifndef CZSPAS_FATAL
	#define CZSPAS_FATAL(fmt, ...)                                        \
		{                                                                 \
			::cz::spas::detail::DefaultLog::out(true, "Fatal: ", fmt, ##__VA_ARGS__); \
			CZSPAS_DEBUG_BREAK();                                         \
			exit(1);                                                      \
		}
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
private:
	std::shared_ptr<std::string> optionalMsg;
};

using PostHandler = std::function<void()>;
using ConnectHandler = std::function<void(const Error& ec)>;
using TransferHandler = std::function<void(const Error& ec, size_t transfered)>;

namespace detail
{

	//////////////////////////////////////////////////////////////////////////
	//! Utility class to make sure a give chunk of code is executed no matter what when unwinding the callstack
	template<class Func>
	class ScopeGuard
	{
	public:
		ScopeGuard(Func f)
			: m_fun(std::move(f))
			, m_active(true)
		{
		}

		~ScopeGuard()
		{
			if (m_active)
				m_fun();
		}

		void dismiss()
		{
			m_active = false;
		}

		ScopeGuard() = delete;
		ScopeGuard(const ScopeGuard&) = delete;
		ScopeGuard& operator=(const ScopeGuard&) = delete;
		ScopeGuard(ScopeGuard&& rhs)
			: m_fun(std::move(rhs.m_fun))
			, m_active(rhs.m_active)
		{
			rhs.dismiss();
		}

	private:
		Func m_fun;
		bool m_active;
	};

	/**
		Using a template function to create guards, since template functions can do type deduction,
		meaning shorter code.

		auto g1 = scopeGuard( [&] { cleanup(); } );
	*/
	template< class Func>
	ScopeGuard<Func> scopeGuard(Func f)
	{
		return ScopeGuard<Func>(std::move(f));
	}

	/**
		Some macro magic so it's easy to set anonymous scope guards. e.g:

		// some code ...
		SCOPE_EXIT { some cleanup code };
		// more code ...
		SCOPE_EXIT { more cleanup code };
		// more code ...
	 */
	enum class ScopeGuardOnExit {};
	template <typename Func>
	__forceinline cz::spas::detail::ScopeGuard<Func> operator+(ScopeGuardOnExit, Func&& fn) {
		return cz::spas::detail::ScopeGuard<Func>(std::forward<Func>(fn));
	}

	#define CZSPAS_CONCATENATE_IMPL(s1,s2) s1##s2
	#define CZSPAS_CONCATENATE(s1,s2) CZSPAS_CONCATENATE_IMPL(s1,s2)

	// Note: __COUNTER__ Expands to an integer starting with 0 and incrementing by 1 every time it is used in a source file or included headers of the source file.
	#ifdef __COUNTER__
		#define CZSPAS_ANONYMOUS_VARIABLE(str) \
			CZSPAS_CONCATENATE(str,__COUNTER__)
	#else
		#define CZSPAS_ANONYMOUS_VARIABLE(str) \
			CZSPAS_CONCATENATE(str,__LINE__)
	#endif

	#define CZSPAS_SCOPE_EXIT \
		auto CZSPAS_ANONYMOUS_VARIABLE(SCOPE_EXIT_STATE) \
		= cz::spas::detail::ScopeGuardOnExit() + [&]()
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
	using IsPostHandler = std::enable_if_t<detail::check_signature<H, void()>::value>;
	template<typename H>
	using IsConnectHandler = std::enable_if_t<detail::check_signature<H, void(const Error&)>::value>;
	template<typename H>
	using IsTransferHandler = std::enable_if_t<detail::check_signature<H, void(const Error&, size_t)>::value>;

	class ErrorWrapper
	{
	public:
#if _WIN32
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
		explicit ErrorWrapper(int err_) : err(err_) {}
		std::string msg() const { return getWin32ErrorMsg(err); }
		bool isBlockError() const { return err == WSAEWOULDBLOCK; }
		int getCode() const { return err; };
#else
		ErrorWrapper() { err = errno; }
		explicit ErrorWrapper(int err_) : err(err_) {}
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
				return;
			int res;
#if _WIN32
			if (doshutdown)
				::shutdown(s, SD_BOTH);
			res = ::closesocket(s);
#else
			if (doshutdown)
				::shutdown(s, SHUT_RDWR);
			res = ::close(s);
#endif

			//
			// According to Unix and Windows documentation, it is possible for the close to fail
			// with EWOULDBLOCK.
			// If that happens, put the socket back to blocking mode and try again
			// Asio also does this (include\asio\detail\impl\socket_ops.ipp : close)
			if (res!=0 && ErrorWrapper().isBlockError())
			{
				detail::utils::setBlocking(s, true);
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
		static void setLinger(SocketHandle s, bool enabled, u_short timeoutSeconds)
		{
			linger l;
			l.l_onoff = enabled ? 1 : 0;
			l.l_linger = timeoutSeconds;
			int res = setsockopt(s, SOL_SOCKET, SO_LINGER, (const char*)&l, sizeof(l));
			if (res != 0)
				CZSPAS_FATAL(ErrorWrapper().msg().c_str());
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
					return ErrorWrapper(result).getError();
				else
					return Error();
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
				return std::make_pair("0.0.0.0", 0);
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
		static std::pair<Error, SocketHandle> createListenSocket(const char* bindIP, int port, int backlog, bool reuseAddr)
		{
			SocketHandle s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (s == CZSPAS_INVALID_SOCKET)
				return std::make_pair(detail::ErrorWrapper().getError(), s);

			if (reuseAddr)
				detail::utils::setReuseAddress(s);

			sockaddr_in addr;
			addr.sin_family = AF_INET;
			addr.sin_port = htons(port);
			if (bindIP)
				inet_pton(AF_INET, bindIP, &(addr.sin_addr));
			else
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

		static std::pair<Error, SocketHandle> createListenSocket(int port)
		{
			return createListenSocket(nullptr, port, SOMAXCONN, false);
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
			else if (res == CZSPAS_SOCKET_ERROR) {
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
				return std::make_pair(res.second, CZSPAS_INVALID_SOCKET);

			sockaddr_in addr;
			socklen_t size = sizeof(addr);
			SocketHandle s = ::accept(acceptor, (struct sockaddr*)&addr, &size);
			if (s == CZSPAS_INVALID_SOCKET)
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

	struct SocketOperation;
	struct AcceptOperation;
	struct ConnectOperation;
	struct SendOperation;
	struct ReceiveOperation;

	class BaseService
	{
	};

	struct SocketHelper
	{
	public:

		SocketHelper(detail::BaseService& owner)
			: owner(owner)
			, pendingAccept(0)
			, pendingConnect(0)
			, pendingSend(0)
			, pendingReceive(0)
		{
		}

		virtual ~SocketHelper()
		{
			CZSPAS_ASSERT(pendingAccept.load() == 0);
			CZSPAS_ASSERT(pendingConnect.load() == 0);
			CZSPAS_ASSERT(pendingSend.load() == 0);
			CZSPAS_ASSERT(pendingReceive.load() == 0);
		}

		//! Only to be used with care, if the user wants to access the underlying socket handle
		SocketHandle getHandle()
		{
			return s;
		}

		Service& getService()
		{
			return *((Service*)&owner);
		}

		void setLinger(bool enabled, unsigned short timeoutSeconds)
		{
			detail::utils::setLinger(s, enabled, timeoutSeconds);
		}

		// For internal use in the unit tests. DO NOT USE
		void _forceClose(bool doshutdown)
		{
			detail::utils::closeSocket(s, doshutdown);
		}

		const std::pair<std::string, int>& getLocalAddr() const
		{
			return localAddr;
		}

		const std::pair<std::string, int>& getPeerAddr() const
		{
			return peerAddr;
		}
			
		SocketHelper(const SocketHelper&) = delete;
		void operator=(const SocketHelper&) = delete;

		bool isValid() const
		{
			return s != CZSPAS_INVALID_SOCKET;
		}

		void resolveAddrs()
		{
			localAddr = detail::utils::getLocalAddr(s);
			peerAddr = detail::utils::getRemoteAddr(s);
		}

		detail::BaseService& owner;
		SocketHandle s = CZSPAS_INVALID_SOCKET;

		// Only for debugging: #TODO : Add a define to have it available only on Debug build
		// NOTE: In the Operation structs, these need to be set to false in both the destructor and BEFORE calling the user handler
		//		1. Its needed in the destructor, because the operation might be destroyed without calling the user handler (e.g: Cancelled)
		//		2. BEFORE calling the user handler, because from the handle the user might want to queue another operation of the same type
		std::atomic<int> pendingAccept; 
		std::atomic<int> pendingConnect;
		std::atomic<int> pendingSend;
		std::atomic<int> pendingReceive;

		std::pair<std::string, int> localAddr;
		std::pair<std::string, int> peerAddr;
	};

	struct Operation
	{
		Error ec;
		std::atomic<int>* dbgCounter = nullptr;
		explicit Operation(std::atomic<int>* dbgCounter)
			: dbgCounter(dbgCounter)
		{
			if (dbgCounter)
				++(*dbgCounter);
		}

		virtual ~Operation()
		{
			// Derived classed must call setFinished where required
			assert(dbgCounter==nullptr);
		}

		void setFinished()
		{
			if (dbgCounter)
			{
				--(*dbgCounter);
				dbgCounter = nullptr;
			}
		}

		virtual void exec(SocketHandle fd, bool hasPOLLHUP) = 0;
		virtual void callUserHandler() = 0;
	};

	struct PostOperation : Operation
	{
		PostHandler userHandler;
		template<typename H>
		PostOperation(Service& io, H&& h)
			: Operation(nullptr)
			, userHandler(std::forward<H>(h))
		{
		}
		virtual void exec(SocketHandle fd, bool hasPOLLHUP) override {}
		virtual void callUserHandler()
		{
			userHandler();
		}
	};

	struct SocketOperation : public Operation
	{
		SocketHelper& owner;
		explicit SocketOperation(SocketHelper& owner, std::atomic<int>* dbgCounter)
			: Operation(dbgCounter)
			, owner(owner)
		{
		}
	};

	struct AcceptOperation : public SocketOperation
	{
		ConnectHandler userHandler;
		SocketHelper& sock;

		template<typename H>
		AcceptOperation(SocketHelper& owner, SocketHelper& dst, H&& h)
			: SocketOperation(owner, &owner.pendingAccept)
			, sock(dst)
			, userHandler(std::forward<H>(h))
		{
		}

		~AcceptOperation()
		{
			setFinished();
		}

		virtual void exec(SocketHandle fd, bool hasPOLLHUP) override
		{
			sockaddr_in addr;
			socklen_t size = sizeof(addr);
			sock.s = ::accept(fd, (struct sockaddr*)&addr, &size);
			if (sock.s == CZSPAS_INVALID_SOCKET)
				ec = detail::ErrorWrapper().getError();
			else
			{
				detail::utils::setBlocking(sock.s, false);
				sock.resolveAddrs();
			}
		}

		virtual void callUserHandler() override
		{
			userHandler(ec);
		}
	};

	struct ConnectOperation : public SocketOperation
	{
		ConnectHandler userHandler;

		template<typename H>
		ConnectOperation(SocketHelper& owner, H&& h)
			: SocketOperation(owner, &owner.pendingConnect)
			, userHandler(std::forward<H>(h))
		{
		}

		~ConnectOperation()
		{
			setFinished();
		}

		virtual void exec(SocketHandle fd, bool hasPOLLHUP) override
		{
			CZSPAS_ASSERT(fd == owner.getHandle());
			ec = detail::utils::getSocketError(fd);
			if (!ec)
				owner.resolveAddrs();
		}

		virtual void callUserHandler() override
		{
			userHandler(ec);
		}
	};

	struct TransferOperation : public SocketOperation
	{
		char* buf;
		size_t bufSize;
		size_t transfered = 0;
		TransferHandler userHandler;

		template<typename H>
		TransferOperation(SocketHelper& owner, std::atomic<int>* dbgCounter, char* buf, size_t len, H&& h)
			: SocketOperation(owner, dbgCounter)
			, buf(buf)
			, bufSize(len)
			, userHandler(std::forward<H>(h))
		{
		}

		~TransferOperation()
		{
			setFinished();
		}
	};

	struct SendOperation : public TransferOperation
	{
		template<typename H>
		SendOperation(SocketHelper& owner, const char* buf, size_t len, H&& h)
			: TransferOperation(owner, &owner.pendingSend, const_cast<char*>(buf), len, std::forward<H>(h))
		{
		}

		virtual void exec(SocketHandle fd, bool hasPOLLHUP) override
		{
			CZSPAS_ASSERT(fd == owner.getHandle());
			// The interface allows size_t, but the implementation only allows int
			int todo = bufSize > INT_MAX ? INT_MAX : static_cast<int>(bufSize);
			int flags = 0;
#if __linux__
			flags = MSG_NOSIGNAL;
#endif
			int done = ::send(fd, buf, todo, flags);
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

		virtual void callUserHandler() override
		{
			userHandler(ec, transfered);
		}
	};

	struct ReceiveOperation : public TransferOperation
	{
		template<typename H>
		ReceiveOperation(SocketHelper& owner, char* buf, size_t len, H&& h)
			: TransferOperation(owner, &owner.pendingReceive, buf, len, std::forward<H>(h))
		{
		}

		virtual void exec(SocketHandle fd, bool hasPOLLHUP) override
		{
			CZSPAS_ASSERT(fd == owner.getHandle());
			// The interface allows size_t, but the implementation only allows int
			int todo = bufSize > INT_MAX ? INT_MAX : static_cast<int>(bufSize);
			int flags = 0;
#if __linux__
			flags = MSG_NOSIGNAL;
#endif
			int done = ::recv(fd, buf, todo, flags);
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

		virtual void callUserHandler() override
		{
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
	SocketHandle m_signalIn = CZSPAS_INVALID_SOCKET;
	SocketHandle m_signalOut = CZSPAS_INVALID_SOCKET;
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
				empty = processEventsHelper(it->first, it->second.ops[EventType::Write],
					fd.revents & POLLWRNORM, hasPOLLHUP, now, dst) && empty;
				if (empty)
					m_sockData.erase(it);
			}
		}
	}

public:

	Reactor()
	{
		// Create a listening socket on a port picked by the OS (because we passed 0 as port)
		auto acceptor = utils::createListenSocket("127.0.0.1", 0, 1, false);
		// If this fails, then the OS probably ran out of resources (e.g: Too many connections or too many connection 
		// on TIME_WAIT)
		CZSPAS_ASSERT(!acceptor.first);

		// NOTE: We can connect without doing the accept first
		{
			auto res = detail::utils::createConnectSocket("127.0.0.1", detail::utils::getLocalAddr(acceptor.second).second);
			// Same as above. If this fails, then the OS ran out of resources
			CZSPAS_ASSERT(!res.first);
			m_signalOut = res.second;
		}

		// Loop until we accept the right connection.
		// This drops any unwanted connections (if it happens some other application tries to connect to our acceptor port)
		while (m_signalIn == CZSPAS_INVALID_SOCKET)
		{
			auto res = detail::utils::accept(acceptor.second);
			if (res.first) // If some error occurred, just try and accept another.
				continue;
			// A simple check to make sure it's the connection we expect.
			// From the acceptor perspective, the remote port of the incoming connection must be the local port of m_signalOut
			if (detail::utils::getRemoteAddr(res.second).second == detail::utils::getLocalAddr(m_signalOut).second)
				m_signalIn = res.second;
			else
				detail::utils::closeSocket(res.second, false);
		}

		detail::utils::closeSocket(acceptor.second);
	}

	~Reactor()
	{
		// To avoid the TIME_WAIT, we do the following:
		// 1. Disable lingering on the client socket (m_signalOut)
		// 2. Close client socket
		// 3. Close server side socket (m_signalIn). This the other socket was the one initiating the shutdown,
		//    this one doesn't go into TIME_WAIT
		detail::utils::setLinger(m_signalOut, true, 0);
		detail::utils::closeSocket(m_signalOut, false);
		detail::utils::closeSocket(m_signalIn, false);
	}

	// Putting this in a method, so Service can call this.
	// This is required, to make sure all Operations (the ones in Service queues, and in Reactor) are destroyed BEFORE
	// Socket instances, otherwise we can get the asserts that there are pending Operations when destroying a Socket
	void deleteOps()
	{
		m_sockData.clear();
	}

	void interrupt()
	{
		char buf = 0;
		int flags = 0;
#if __linux__
		flags = MSG_NOSIGNAL;
#endif
		if (::send(m_signalOut, &buf, 1, flags) != 1)
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
};

} // namespace detail

//////////////////////////////////////////////////////////////////////////
//	Service interface
//////////////////////////////////////////////////////////////////////////
class Service : public detail::BaseService
{
public:

	// #TODO Document this
	class Work
	{
	public:
		explicit Work(Service& io) : m_io(&io)
		{
			m_io->workStarted();
		}
		explicit Work(const Work& other) : m_io(other.m_io)
		{
			m_io->workStarted();
		}
		explicit Work(Work&& other) : m_io(other.m_io)
		{
			other.m_io = nullptr;
		}
		// No need to complicate further by allowing assignment. Constructors are enough.
		Work& operator=(const Work& other) = delete;

		~Work()
		{
			if (m_io)
				m_io->workFinished();
		}
	private:
		Service* m_io;
	};

	Service()
	{
	}
	~Service()
	{
		// Making sure all Operation objects are destroyed before Sockets, so we don't get the "pending" operations
		// asserts while destroying sockets.
		m_reactor.deleteOps();
	}

	size_t run()
	{
		if (m_outstandingWork == 0)
		{
			stop();
			return 0;
		}

		// NOTE: At first, I was resetting m_stopped to false here, but that is problematic:
		// E.g:
		// - One thread id created to call run
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
					std::swap(m_tmpready, m_ready);
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
			// - Thread B calls Acceptor::cancel . This adds the cancelled handler to m_ready
			// - Thread A will gets unblocked, and does
			//		- runReadyHandlers(m_tmpready); // Nothing done, since the only m_ready has handlers
			//		- loop and do std::swap(m_tmpread, m_ready) 
			//		- next m_reactor.runOnce will block forever, even tho we have handlers in m_tmpready
			//
			done += runReadyHandlers(m_tmpready);
			m_reactor.runOnce(m_tmpready);
			done += runReadyHandlers(m_tmpready);
		}

		return done;
	}

	size_t runReadyHandlers(std::queue<std::unique_ptr<detail::Operation>>& q)
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

	template<typename H, typename = detail::IsPostHandler<H>>
	void post(H&& h)
	{
		post(std::make_unique<detail::PostOperation>(*this, std::forward<H>(h)));
	}

	void stop()
	{
		m_stopped = true;
		m_reactor.interrupt();
	}

	bool isStopped() const
	{
		return m_stopped.load();
	}

	void reset()
	{
		m_stopped = false;
	}

private:

	void workStarted()
	{
		++m_outstandingWork;
	}

	void workFinished()
	{
		auto n = --m_outstandingWork;
		CZSPAS_ASSERT(n >= 0);
		if (n==0)
		{
			stop();
		}
	}

	void cancel(SocketHandle fd)
	{
		std::lock_guard<std::mutex> lk(m_mtx);
		m_reactor.cancel(fd, m_ready);
	}

	void post(std::unique_ptr<detail::Operation> op)
	{
		std::lock_guard<std::mutex> lk(m_mtx);
		workStarted();
		m_ready.push(std::move(op));
		m_reactor.interrupt();
	}

	void addOperation(SocketHandle fd, detail::Reactor::EventType type, std::unique_ptr<detail::Operation> op, int timeoutMs)
	{
		workStarted();
		m_reactor.addOperation(fd, type, std::move(op), timeoutMs);
	}

	friend class Acceptor;
	friend class Socket;
	friend class Work;
	std::mutex m_mtx;
	detail::Reactor m_reactor;
	std::queue<std::unique_ptr<detail::Operation>> m_ready;
	std::queue<std::unique_ptr<detail::Operation>> m_tmpready;
	std::atomic<bool> m_stopped{false};
	std::atomic<int> m_outstandingWork{ 0 };
};

//////////////////////////////////////////////////////////////////////////
//	Socket interface
//////////////////////////////////////////////////////////////////////////
class Socket
{
public:
	Socket(Service& service)
		: m_base(service)
	{
	}

	Socket(const Socket&) = delete;
	Socket& operator= (const Socket&) = delete;
	Socket(Socket&&) = delete;
	Socket& operator= (Socket&&) = delete;

	~Socket()
	{
		detail::utils::closeSocket(m_base.s);
	}

	//! Synchronous connect
	Error connect(const char* ip, int port)
	{
		CZSPAS_ASSERT(!m_base.isValid());

		CZSPAS_INFO("Socket %p: Connect(%s,%d)", this, ip, port);
		auto res = detail::utils::createConnectSocket(ip, port);
		if (res.first)
		{
			CZSPAS_ERROR("Socket %p: %s", this, res.first.msg());
			return res.first;
		}
		m_base.s = res.second;
		m_base.resolveAddrs();
		CZSPAS_INFO("Socket %p: Connected to %s:%d", this, m_peerAddr.first.c_str(), m_peerAddr.second);
		return Error();
	}

	void asyncConnect(const char* ip, int port, int timeoutMs, ConnectHandler h)
	{
		CZSPAS_ASSERT(!m_base.isValid());
		CZSPAS_ASSERT(m_base.pendingConnect.load()==0 && "There is already a pending connect operation");
		CZSPAS_INFO("Socket %p: asyncConnect(%s,%d, H, %d)", this, ip, port, timeoutMs);

		auto op = std::make_unique<detail::ConnectOperation>(m_base, std::move(h));

		m_base.s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (m_base.s == CZSPAS_INVALID_SOCKET)
		{
			op->ec = detail::ErrorWrapper().getError();
			CZSPAS_ERROR("Socket %p: %s", this, op->ec.msg());
			getService().post(std::move(op));
			return;
		}

		// Enable any loopback optimizations (in case this socket is used in loopback)
		detail::utils::optimizeLoopback(m_base.s);
		// Set to non-blocking, so we can do an asynchronous connect
		detail::utils::setBlocking(m_base.s, false);

		sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		inet_pton(AF_INET, ip, &(addr.sin_addr));

		if (::connect(m_base.s, (const sockaddr*)&addr, sizeof(addr)) == CZSPAS_SOCKET_ERROR)
		{
			detail::ErrorWrapper err;
			if (err.isBlockError())
			{
				// Normal behaviour.
				// A asynchronous connect is done when we receive a write event on the socket
				getService().addOperation(m_base.s, detail::Reactor::EventType::Write, std::move(op), timeoutMs);
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
			getService().addOperation(m_base.s, detail::Reactor::EventType::Write, std::move(op), timeoutMs);
		}
	}

	template< typename H, typename = detail::IsConnectHandler<H> >
	void asyncConnect(const char* ip, int port, H&& h)
	{
		asyncConnect(ip, port, -1, std::forward<H>(h));
	}

	size_t sendSome(const char* buf, size_t len, int timeoutMs, Error& ec)
	{
		CZSPAS_ASSERT(len > 0);
		auto res = detail::utils::doSelect(m_base.s, false, timeoutMs);
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
		int done = ::send(m_base.s, buf, todo, flags);
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

	size_t sendSome(const char* buf, size_t len, Error& ec)
	{
		return sendSome(buf, len, -1, ec);
	}

	template< typename H, typename = detail::IsTransferHandler<H> >
	void asyncSendSome(const char* buf, size_t len, int timeoutMs, H&& h)
	{
		CZSPAS_ASSERT(len > 0);
		CZSPAS_ASSERT(m_base.isValid());
		CZSPAS_ASSERT(m_base.pendingSend.load()==0 && "There is already a pending send operation");
		auto op = std::make_unique<detail::SendOperation>(m_base, buf, len, std::forward<H>(h));
		getService().addOperation(m_base.s, detail::Reactor::EventType::Write, std::move(op), timeoutMs);
	}

	template< typename H, typename = detail::IsTransferHandler<H> >
	void asyncSendSome(const char* buf, size_t len, H&& h)
	{
		asyncSendSome(buf, len, -1, std::forward<H>(h));
	}

	size_t receiveSome(char* buf, size_t len, int timeoutMs, Error& ec)
	{
		CZSPAS_ASSERT(len > 0);
		auto res = detail::utils::doSelect(m_base.s, true, timeoutMs);
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
		int done = ::recv(m_base.s, buf, todo, flags);
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

	size_t receiveSome(char* buf, size_t len, Error& ec)
	{
		return receiveSome(buf, len, -1, ec);
	}

	template< typename H, typename = detail::IsTransferHandler<H> >
	void asyncReceiveSome(char* buf, size_t len, int timeoutMs, H&& h)
	{
		CZSPAS_ASSERT(len > 0);
		CZSPAS_ASSERT(m_base.isValid());
		CZSPAS_ASSERT(m_base.pendingReceive.load()==0 && "There is already a pending receive operation");
		auto op = std::make_unique<detail::ReceiveOperation>(m_base, buf, len, std::forward<H>(h));
		getService().addOperation(m_base.s, detail::Reactor::EventType::Read, std::move(op), timeoutMs);
	}

	template< typename H, typename = detail::IsTransferHandler<H> >
	void asyncReceiveSome(char* buf, size_t len, H&& h)
	{
		asyncReceiveSome(buf, len, -1, std::forward<H>(h));
	}

	void cancel()
	{
		if (m_base.isValid())
			getService().cancel(m_base.s);
	}

	void close()
	{
		cancel();
		if (m_base.isValid())
			detail::utils::closeSocket(m_base.s, false);
	}

	Service& getService()
	{
		return m_base.getService();
	}

	void setLinger(bool enabled, unsigned short timeoutSeconds)
	{
		m_base.setLinger(enabled, timeoutSeconds);
	}

	const std::pair<std::string, int>& getLocalAddr() const
	{
		return m_base.getLocalAddr();
	}

	const std::pair<std::string, int>& getPeerAddr() const
	{
		return m_base.getPeerAddr();
	}

	//! Only to be used with care, if the user wants to access the underlying socket handle
	SocketHandle getHandle()
	{
		return m_base.getHandle();
	}

	// For internal use in the unit tests. DO NOT USE
	void _forceClose(bool doshutdown)
	{
		m_base._forceClose(doshutdown);
	}

private:
	friend Acceptor;
	detail::SocketHelper m_base;
};

//////////////////////////////////////////////////////////////////////////
//	Acceptor interface
//////////////////////////////////////////////////////////////////////////
class Acceptor
{
public:
	Acceptor(Service& service)
		: m_base(service)
	{
	}

	virtual ~Acceptor()
	{
		// Close the socket without calling shutdown, and setting linger to 0, so it doesn't linger around and we can
		// run another server right after
		// Not sure this is necessary for listening sockets. ;(
		if (m_base.s != CZSPAS_INVALID_SOCKET)
			detail::utils::setLinger(m_base.s, true, 0);
		detail::utils::closeSocket(m_base.s, false);
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
	Error listen(const char* bindIP, int port, int backlog, bool reuseAddr)
	{
		CZSPAS_ASSERT(!m_base.isValid());
		CZSPAS_INFO("Acceptor %p: listen(%d, %d)", this, port, backlog);

		auto res = detail::utils::createListenSocket(bindIP, port, backlog, reuseAddr);
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

	Error listen(int port)
	{
		bool reuseAddr = false;
#if __linux__
        reuseAddr = true;
#endif
		return listen(nullptr, port, SOMAXCONN, reuseAddr);
	}

	Error accept(Socket& sock, int timeoutMs = -1)
	{
		CZSPAS_ASSERT(m_base.isValid());
		CZSPAS_ASSERT(!sock.m_base.isValid());

		auto res = detail::utils::accept(m_base.s, timeoutMs);
		if (res.first)
		{
			CZSPAS_ERROR("Acceptor %p: %s", this, res.first.msg());
			return res.first;
		}
		sock.m_base.s = res.second;
		sock.m_base.resolveAddrs();
		CZSPAS_INFO("Acceptor %p: Socket %p connected to %s:%d", this, &sock, sock.m_peerAddr.first.c_str(),
		            sock.m_peerAddr.second);

		// No error
		return Error();
	}

	template< typename H, typename = detail::IsConnectHandler<H> >
	void asyncAccept(Socket& sock, int timeoutMs, H&& h)
	{
		CZSPAS_ASSERT(m_base.isValid());
		CZSPAS_ASSERT(!sock.m_base.isValid());
		CZSPAS_ASSERT(m_base.pendingAccept.load()==0 && "There is already a pending accept operation");
		auto op = std::make_unique<detail::AcceptOperation>(m_base, sock.m_base, std::forward<H>(h));
		getService().addOperation(m_base.s, detail::Reactor::EventType::Read, std::move(op), timeoutMs);
	}

	template< typename H, typename = detail::IsConnectHandler<H> >
	void asyncAccept(Socket& sock, H&& h)
	{
		asyncAccept(sock, -1, std::forward<H>(h));
	}

	void cancel()
	{
		if (m_base.isValid())
			m_base.getService().cancel(m_base.s);
	}

	void close()
	{
		cancel();
		if (m_base.isValid())
			detail::utils::closeSocket(m_base.s, false);
	}

	Service& getService()
	{
		return m_base.getService();
	}

	void setLinger(bool enabled, unsigned short timeout)
	{
		m_base.setLinger(enabled, timeout);
	}

	const std::pair<std::string, int>& getLocalAddr() const
	{
		return m_base.getLocalAddr();
	}

	//! Only to be used with care, if the user wants to access the underlying socket handle
	SocketHandle getHandle()
	{
		return m_base.getHandle();
	}

	// For internal use in the unit tests. DO NOT USE
	void _forceClose(bool doshutdown)
	{
		m_base._forceClose(doshutdown);
	}

private:
	detail::SocketHelper m_base;
};

namespace detail
{
	template< typename H, typename = detail::IsTransferHandler<H> >
	void asyncSendHelper(Socket& sock, const char* buf, size_t len, int timeoutMs, const Error& ec, size_t totalDone, H&& h)
	{
		CZSPAS_ASSERT(totalDone <= len);
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
		CZSPAS_ASSERT(totalDone <= len);
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
void asyncSend(Socket& sock, const char* buf, size_t len, H&& h)
{
	CZSPAS_ASSERT(len > 0);
	detail::asyncSendHelper(sock, buf, len, -1, Error(), 0, std::forward<H>(h));
}

template< typename H, typename = detail::IsTransferHandler<H> >
void asyncSend(Socket& sock, const char* buf, size_t len, int timeoutMs, H&& h)
{
	CZSPAS_ASSERT(len > 0);
	detail::asyncSendHelper(sock, buf, len, timeoutMs, Error(), 0, std::forward<H>(h));
}

template< typename H, typename = detail::IsTransferHandler<H> >
void asyncReceive(Socket& sock, char* buf, size_t len, H&& h)
{
	CZSPAS_ASSERT(len > 0);
	detail::asyncReceiveHelper(sock, buf, len, -1, Error(), 0, std::forward<H>(h));
}

template< typename H, typename = detail::IsTransferHandler<H> >
void asyncReceive(Socket& sock, char* buf, size_t len, int timeoutMs, H&& h)
{
	CZSPAS_ASSERT(len > 0);
	detail::asyncReceiveHelper(sock, buf, len, timeoutMs, Error(), 0, std::forward<H>(h));
}

// Putting the synchronous send/receive in a struct, so the implementation can be in the header file.
// This is needed, since send/receive are not templated.
namespace detail
{
	struct syncImpl
	{
		static size_t send(Socket& sock, const char* buf, size_t len, int timeoutMs, Error& ec)
		{
			size_t transfered = 0;
			while (!ec && transfered < len)
				transfered += sock.sendSome(buf + transfered, len - transfered, timeoutMs, ec);
			return transfered;
		}

		static size_t receive(Socket& sock, char* buf, size_t len, int timeoutMs, Error& ec)
		{
			size_t transfered = 0;
			while (!ec && transfered < len)
				transfered += sock.receiveSome(buf + transfered, len - transfered, timeoutMs, ec);
			return transfered;
		}
	};
}

inline size_t send(Socket& sock, const char* buf, size_t len, int timeoutMs, Error& ec)
{
	CZSPAS_ASSERT(len > 0);
	return detail::syncImpl::send(sock, buf, len, timeoutMs, ec);
}

inline size_t send(Socket& sock, const char* buf, size_t len, Error& ec)
{
	CZSPAS_ASSERT(len > 0);
	return detail::syncImpl::send(sock, buf, len, -1, ec);
}

inline size_t receive(Socket& sock, char* buf, size_t len, int timeoutMs, Error& ec)
{
	CZSPAS_ASSERT(len > 0);
	return detail::syncImpl::receive(sock, buf, len, timeoutMs, ec);
}

inline size_t receive(Socket& sock, char* buf, size_t len, Error& ec)
{
	CZSPAS_ASSERT(len > 0);
	return detail::syncImpl::receive(sock, buf, len, -1, ec);
}

} // namespace spas
} // namespace cz
