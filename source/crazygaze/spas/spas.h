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
	strncpy_s(dst, sizeof(dst), src, strlen(src));
#else
	strncpy(dst, src, strlen(src));
#endif
}

struct DefaultLog
{
	static void out(bool fatal, const char* type, const char* fmt, ...)
	{
		char buf[256];
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
	// Note that it return true IF THERE IS AN ERROR, not the other way around.
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
		BaseSocket() {}
		virtual ~BaseSocket()
		{
		}

		bool isValid() const
		{
			return m_s != CZSPAS_INVALID_SOCKET;
		}

	protected:

		BaseSocket(const BaseSocket&) = delete;
		void operator=(const BaseSocket&) = delete;

		friend ServiceData;
		friend Service;
		SocketHandle m_s = CZSPAS_INVALID_SOCKET;
	};

	// This is not part of the Service class, so we can break the circular dependency
	// between Acceptor/Socket and Service
	class ServiceData
	{
	public:
		ServiceData()
			: m_stopped(false)
			, m_signalFlight(0)
		{
		}


	protected:

		friend Socket;
		friend Acceptor;

#if _WIN32
		details::WSAInstance m_wsaInstance;
#endif
		std::unique_ptr<BaseSocket> m_signalIn;
		std::unique_ptr<BaseSocket> m_signalOut;

		std::atomic<int> m_signalFlight;
		std::atomic<bool> m_stopped; // A "stop" command was enqueued
		bool m_finishing = false; // The stop command was found, and we are in the process of executing any remaining commands

		struct ConnectOp
		{
			std::chrono::time_point<std::chrono::high_resolution_clock> timeoutPoint;
			ConnectHandler h;
		};

		std::unordered_map<Socket*, ConnectOp> m_connects;  // Pending connects
		std::set<Acceptor*> m_accepts; // pending accepts
		std::set<Socket*> m_recvs; // pending reads
		std::set<Socket*> m_sends; // pending writes

		using CmdQueue = std::queue<std::function<void()>>;
		Monitor<CmdQueue> m_cmdQueue;
		CmdQueue m_tmpQueue;
		char m_signalInBuf[1];
		void signal()
		{
			if (!m_signalOut)
				return;
			if (m_signalFlight.load() > 0)
				return;
			char buf = 0;
			++m_signalFlight;
			if (::send(m_signalOut->m_s, &buf, 1, 0) != 1)
				CZSPAS_FATAL(details::ErrorWrapper().msg().c_str());
		}

		template< typename H, typename = IsSimpleHandler<H> >
		void addCmd(H&& h)
		{
			m_cmdQueue([&](CmdQueue& q)
			{
				q.push(std::move(h));
			});
			signal();
		}

		// Used only for debugging, so the Socket/Acceptor can execute thread safe asserts with the owner
		template< typename H>
		auto execSafe(H&& h)
		{
			return m_cmdQueue([&](CmdQueue& q)
			{
				return h();
			});
		}


	};
} // namespace details


//////////////////////////////////////////////////////////////////////////
// Socket
//////////////////////////////////////////////////////////////////////////
/*!
Main socket class, used to send and receive data

Thread Safety:
	Distinct objects  : Safe
	Shared objects : Unsafe
*/
class Socket : public details::BaseSocket
{
public:

	Socket(details::ServiceData& serviceData)
		: m_owner(serviceData)
	{
	}

	virtual ~Socket()
	{
		CZSPAS_ASSERT(m_recvs.size() == 0);
		CZSPAS_ASSERT(m_sends.size() == 0);
		releaseHandle();
	}

	// #TODO : Remove or make private/protected
	// Move to BaseSocket
	void releaseHandle()
	{
		//printf("%p : releaseHandle()\n", this);
		CZSPAS_ASSERT(m_recvs.size() == 0);
		CZSPAS_ASSERT(m_sends.size() == 0);
		CZSPAS_ASSERT(m_owner.execSafe([this]
		{
			return
				m_owner.m_sends.find(this) == m_owner.m_sends.end() &&
				m_owner.m_recvs.find(this) == m_owner.m_recvs.end();
		}));

		details::utils::closeSocket(m_s);
		m_s = CZSPAS_INVALID_SOCKET;
	}

	Error connect(const char* ip, int port)
	{
		CZSPAS_ASSERT(m_s == CZSPAS_INVALID_SOCKET);
		CZSPAS_ASSERT(!m_owner.m_stopped);

		m_s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (m_s == CZSPAS_INVALID_SOCKET)
		{
			auto ec = details::ErrorWrapper().getError();
			CZSPAS_ERROR(ec.msg());
			return ec;
		}

		CZSPAS_INFO("Connect socket=%d", (int)m_s);
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
			CZSPAS_ERROR(ec.msg());
			releaseHandle();
			return ec;
		}

		details::utils::setBlocking(m_s, false);

		m_localAddr = details::utils::getLocalAddr(m_s);
		m_peerAddr = details::utils::getRemoteAddr(m_s);
		CZSPAS_INFO("Socket %d connected to %s:%d", (int)m_s, m_peerAddr.first.c_str(), m_peerAddr.second);

		return Error();
	}

	void asyncConnect(const char* ip, int port, ConnectHandler h, int timeoutMs = 200)
	{
		CZSPAS_ASSERT(m_s == CZSPAS_INVALID_SOCKET);
		CZSPAS_ASSERT(!m_owner.m_stopped);

		m_s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		// If the socket creation fails, send the handler to the service thread to execute with an error
		if (m_s == CZSPAS_INVALID_SOCKET)
		{
			Error ec = details::ErrorWrapper().getError();
			m_owner.addCmd([ec = std::move(ec), h = std::move(h)]
			{
				h(ec);
			});
			return;
		}
		CZSPAS_INFO("Connect socket=%d", (int)m_s);

		// Enable any loopback optimizations (in case this socket is used in loopback)
		details::utils::optimizeLoopback(m_s);
		// Set to non-blocking, so we can do an asynchronous connect
		details::utils::setBlocking(m_s, false);

		sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		inet_pton(AF_INET, ip, &(addr.sin_addr));

		if (::connect(m_s, (const sockaddr*)&addr, sizeof(addr)) == CZSPAS_SOCKET_ERROR)
		{
			details::ErrorWrapper err;
			if (err.isBlockError())
			{
				// Normal behavior, so setup the connect detection with select
				m_owner.addCmd([this, h = std::move(h), timeoutMs]
				{
					details::ServiceData::ConnectOp op;
					op.timeoutPoint = std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(timeoutMs);
					op.h = std::move(h);
					m_owner.m_connects[this] = std::move(op);
				});
			}
			else
			{
				// Anything else than a blocking error is a real error
				m_owner.addCmd([this, ec = err.getError(), h = std::move(h)]
				{
					releaseHandle();
					h(ec);
				});
			}
		}
		else
		{
			// It may happen that the connect succeeds right away.
			m_owner.addCmd([h = std::move(h)]
			{
				h(Error());
			});
		}
	}

	//
	// Asynchronous reading
	//
	template< typename H, typename = details::IsTransferHandler<H> >
	void asyncReadSome(char* buf, int len, H&& h)
	{
		asyncReadImpl(buf, len, std::forward<H>(h), false);
	}
	template< typename H, typename = details::IsTransferHandler<H> >
	void asyncReadSome(TCPBuffer& buf, H&& h)
	{
		asyncReadImpl(buf.buf.get(), buf.size, std::forward<H>(h), false);
	}
	template< typename H, typename = details::IsTransferHandler<H> >
	void asyncRead(char* buf, int len, H&& h)
	{
		asyncReadImpl(buf, len, std::forward<H>(h), true);
	}
	template< typename H, typename = details::IsTransferHandler<H> >
	void asyncRead(TCPBuffer& buf, H&& h)
	{
		asyncReadImpl(buf.buf.get(), buf.size, std::forward<H>(h), true);
	}

	//
	// Asynchronous sending
	//
	template< typename H, typename = details::IsTransferHandler<H> >
	void asyncWrite(const char* buf, int len, H&& h)
	{
		SendOp op;
		op.buf = buf;
		op.bufLen = len;
		op.h = std::move(h);
		m_owner.addCmd([this, op = std::move(op)]
		{
			if (!isValid())
			{
				op.h(Error(Error::Code::Other, "asyncWrite called on a closed socket"), 0);
				return;
			}
			m_sends.push(std::move(op));
			m_owner.m_sends.insert(this);
		});
	}

	template< typename H, typename = details::IsTransferHandler<H> >
	void asyncWrite(const TCPBuffer& buf, H&& h)
	{
		asyncWrite(buf.buf.get(), buf.size, std::forward<H>(h));
	}

	//! Cancels all outstanding asynchronous operations
	template< typename H, typename = details::IsSimpleHandler<H> >
	void asyncCancel(H&& h)
	{
		m_owner.addCmd([this, h=std::move(h)]
		{
			doCancel();
			m_owner.m_recvs.erase(this);
			m_owner.m_sends.erase(this);
			h();
		});
	}

	template< typename H, typename = details::IsSimpleHandler<H> >
	void asyncClose(H&& h)
	{
		asyncCancel([this, h=std::move(h)]()
		{
			releaseHandle();
			h();
		});
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

	template< typename H, typename = details::IsTransferHandler<H> >
	void asyncReadImpl(char* buf, int len, H&& h, bool fill)
	{
		RecvOp op;
		op.buf = buf;
		op.bufLen = len;
		op.fill = fill;
		op.h = std::move(h);
		m_owner.addCmd([this, op = std::move(op)]
		{
			if (!isValid())
			{
				op.h(Error(Error::Code::Other, "asyncRead/asyncReadSome called on a closed socket"), 0);
				return;
			}

			m_recvs.push(std::move(op));
			m_owner.m_recvs.insert(this);
		});
	}

	struct RecvOp
	{
		char* buf = nullptr;
		int bufLen = 0;
		// If true, it will keep reading into this operation, until the specified buffer is full.
		// Only then the handler is called, and the operation discarded;
		// If false, the handler will be called with whatever data is received (even if less than the
		// buffer size, and the operation discarded;
		bool fill = false;
		int bytesTransfered = 0;
		TransferHandler h;
	};
	struct SendOp
	{
		const char* buf = nullptr;
		int bufLen = 0;
		int bytesTransfered = 0;
		TransferHandler h;
	};

	friend Service;
	friend Acceptor;
	details::ServiceData& m_owner;
	std::pair<std::string, int> m_localAddr;
	std::pair<std::string, int> m_peerAddr;

	bool doRecv()
	{
		// NOTE:
		// The Operation is moved to a local variable and pop before calling the handler, otherwise the Socket
		// destructor can assert as the result of pop itself since the container is not empty.

		CZSPAS_ASSERT(m_recvs.size());
		while (m_recvs.size())
		{
			RecvOp& op = m_recvs.front();
			int len = ::recv(m_s, op.buf + op.bytesTransfered, op.bufLen - op.bytesTransfered, 0);
			if (len == CZSPAS_SOCKET_ERROR)
			{
				details::ErrorWrapper err;
				if (err.isBlockError())
				{
					if (op.bytesTransfered && !op.fill)
					{
						// If this operation doesn't require a full buffer, we call the handler with
						// whatever data we received, and discard the operation
						m_owner.addCmd([op = std::move(op)]
						{
							op.h(Error(), op.bytesTransfered);
						});
						m_recvs.pop();
					}

					// Done receiving, since the socket doesn't have more incoming data
					break;
				}
				else
				{
					CZSPAS_ERROR(err.msg().c_str());
					m_owner.addCmd([op=std::move(op), err]
					{
						op.h(Error(Error::Code::ConnectionClosed, err.msg()), op.bytesTransfered);
					});
					m_recvs.pop();
				}
			}
			else if (len > 0)
			{
				op.bytesTransfered += len;
				if (op.bufLen == op.bytesTransfered)
				{
					m_owner.addCmd([op=std::move(op)]
					{
						op.h(Error(), op.bytesTransfered);
					});
					m_recvs.pop();
				}
			}
			else if (len == 0)
			{
				// Move to a local variable and pop before calling, otherwise Socket destructor
				// can assert as the result of popping itself since the container is not empty.
				m_owner.addCmd([op=std::move(op)]
				{
					op.h(Error(Error::Code::ConnectionClosed), op.bytesTransfered);
				});
				m_recvs.pop();
				break;
			}
			else
			{
				CZSPAS_ASSERT(0 && "This should not happen");
			}
		}

		return m_recvs.size() > 0;
	}

	bool doSend()
	{
		// NOTE:
		// The Operation is moved to a local variable and pop before calling the handler, otherwise the Socket
		// destructor can assert as the result of pop itself since the container is not empty.

		while (m_sends.size())
		{
			SendOp& op = m_sends.front();
			auto res = ::send(m_s, op.buf + op.bytesTransfered, op.bufLen - op.bytesTransfered, 0);
			if (res == CZSPAS_SOCKET_ERROR)
			{
				details::ErrorWrapper err;
				if (err.isBlockError())
				{
					// We can't send more data at the moment, so we are done trying
					break;
				}
				else
				{
					CZSPAS_ERROR(err.msg().c_str());
					m_owner.addCmd([op=std::move(op), err]
					{
						op.h(Error(Error::Code::ConnectionClosed, err.msg()), op.bytesTransfered);
					});
					m_sends.pop();
				}
			}
			else
			{
				op.bytesTransfered += res;
				if (op.bufLen == op.bytesTransfered)
				{
					m_owner.addCmd([op=std::move(op)]
					{
						op.h(Error(), op.bytesTransfered);
					});
					m_sends.pop();
				}
			}
		}

		return m_sends.size() > 0;
	}

	void doCancel()
	{
		while (m_recvs.size())
		{
			m_owner.addCmd([op=std::move(m_recvs.front())]
			{
				op.h(Error::Code::Cancelled, op.bytesTransfered);
			});
			m_recvs.pop();
		}

		while (m_sends.size())
		{
			m_owner.addCmd([op=std::move(m_sends.front())]
			{
				op.h(Error::Code::Cancelled, op.bytesTransfered);
			});
			m_sends.pop();
		}
	}

	std::queue<RecvOp> m_recvs;
	std::queue<SendOp> m_sends;
};

//////////////////////////////////////////////////////////////////////////
// Acceptor
//////////////////////////////////////////////////////////////////////////
/*!
With Acceptor you can listen for new connections on a specified port.
Thread Safety:
	Distinct objects  : Safe
	Shared objects : Unsafe
*/
class Acceptor : public details::BaseSocket
{
public:

	Acceptor(details::ServiceData& serviceData)
		: m_owner(serviceData)
	{
	}

	virtual ~Acceptor()
	{
		CZSPAS_ASSERT(m_accepts.size() == 0);
		releaseHandle();
	}

	void releaseHandle()
	{
		CZSPAS_ASSERT(m_accepts.size() == 0);
		CZSPAS_ASSERT(m_owner.execSafe([this]
		{
			return m_owner.m_accepts.find(this) == m_owner.m_accepts.end();
		}));
		details::utils::closeSocket(m_s);
		m_s = CZSPAS_INVALID_SOCKET;
	}

	using AcceptHandler = std::function<void(const Error& ec)>;
	template<typename H>
	using IsAcceptHandler = std::enable_if_t<details::check_signature<H, void(const Error&)>::value>;

	//! Starts listening for new connections at the specified port
	/*
	\param port
		What port to listen on. If 0, the OS will pick a port from the dynamic range
	\param ec
		If an error occurs, this contains the error.
	\param backlog
		Size of the the connection backlog.
		Also, this is only an hint to the OS. It's not guaranteed.
	\return
		The Acceptor socket, or nullptr, if there was an error
	*/
	Error listen(int port, int backlog)
	{
		CZSPAS_ASSERT(!isValid());

		m_s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (m_s == CZSPAS_INVALID_SOCKET)
		{
			auto ec = details::ErrorWrapper().getError();
			CZSPAS_ERROR(ec.msg());
			return ec;
		}

		details::utils::setReuseAddress(m_s);

		CZSPAS_INFO("Listen socket=%d", (int)m_s);
		sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
		if (::bind(m_s, (const sockaddr*)&addr, sizeof(addr)) == CZSPAS_SOCKET_ERROR)
		{
			auto ec = details::ErrorWrapper().getError();
			CZSPAS_ERROR(ec.msg());
			releaseHandle();
			return ec;
		}

		if (::listen(m_s, backlog) == CZSPAS_SOCKET_ERROR)
		{
			auto ec = details::ErrorWrapper().getError();
			CZSPAS_ERROR(ec.msg());
			releaseHandle();
			return ec;
		}

		// Enable any loopback optimizations (in case this socket is used in loopback)
		details::utils::optimizeLoopback(m_s);

		m_localAddr = details::utils::getLocalAddr(m_s);

		return Error();
	}

	//! Starts an asynchronous accept
	template< typename H, typename = IsAcceptHandler<H> >
	void asyncAccept(Socket& sock, H&& h)
	{
		m_owner.addCmd([this, sock=&sock, h(std::move(h))]
		{
			m_accepts.push({*sock, std::move(h)});
			m_owner.m_accepts.insert(this);
		});
	}

	//! Cancels all outstanding asynchronous operations
	template<typename H, typename = details::IsSimpleHandler<H> >
	void asyncCancel(H&& h)
	{
		m_owner.addCmd([this, h=std::move(h)]
		{
			doCancel();
			m_owner.m_accepts.erase(this);
			h();
		});
	}

	//! Disconnects the socket
	template<typename H, typename = details::IsSimpleHandler<H> >
	void asyncClose(H&& h)
	{
		asyncCancel([this, h=std::move(h)]()
		{
			releaseHandle();
			h();
		});
	}

	const std::pair<std::string, int>& getLocalAddress() const
	{
		return m_localAddr;
	}

protected:
	friend class Service;

	struct AcceptOp
	{
		Socket& sock;
		AcceptHandler h;
	};

	// Called from SocketSet
	// Returns true if we still have pending accepts, false otherwise
	bool doAccept()
	{
		CZSPAS_ASSERT(m_accepts.size());

		AcceptOp op = std::move(m_accepts.front());
		m_accepts.pop();

		CZSPAS_ASSERT(op.sock.m_s == CZSPAS_INVALID_SOCKET);
		sockaddr_in clientAddr;
		socklen_t size = sizeof(clientAddr);
		op.sock.m_s = ::accept(m_s, (struct sockaddr*)&clientAddr, &size);
		if (op.sock.m_s == CZSPAS_INVALID_SOCKET)
		{
			auto ec = details::ErrorWrapper().getError();
			CZSPAS_ERROR(ec.msg());
			m_owner.addCmd([op=std::move(op), ec]
			{
				op.h(ec);
			});
			return m_accepts.size() > 0;
		}
		op.sock.m_localAddr = details::utils::getLocalAddr(op.sock.m_s);
		op.sock.m_peerAddr = details::utils::getRemoteAddr(op.sock.m_s);
		details::utils::setBlocking(op.sock.m_s, false);
		CZSPAS_INFO("Server side socket %d connected to %s:%d, socket %d",
			(int)op.sock.m_s, op.sock.m_peerAddr.first.c_str(), op.sock.m_peerAddr.second,
			(int)m_s);
		m_owner.addCmd([op=std::move(op)]
		{
			op.h(Error());
		});

		return m_accepts.size() > 0;
	}

	void doCancel()
	{
		while (m_accepts.size())
		{
			m_owner.addCmd([op=std::move(m_accepts.front())]
			{
				op.h(Error::Code::Cancelled);
			});
			m_accepts.pop();
		}
	}

	details::ServiceData& m_owner;
	std::queue<AcceptOp> m_accepts;
	std::pair<std::string, int> m_localAddr;
};




//////////////////////////////////////////////////////////////////////////
// Service
//////////////////////////////////////////////////////////////////////////
/*
Thread Safety:
	Distinct objects  : Safe
	Shared objects : Unsafe
*/
class Service : public details::ServiceData
{
private:
	struct Callstack
	{
	};

public:
	Service()
	{
		Acceptor dummyListen(*this);
		Error ec = dummyListen.listen(0, 1);
		CZSPAS_ASSERT(!ec);
		m_signalIn = std::make_unique<Socket>(*this);
		bool signalInConnected = false;
		dummyListen.asyncAccept(*reinterpret_cast<Socket*>(m_signalIn.get()), [this, &signalInConnected](const Error& ec)
		{
			CZSPAS_ASSERT(!ec);
			signalInConnected = true;
			CZSPAS_INFO("m_signalIn socket=%d", (int)(m_signalIn->m_s));
		});

		// Do this temporary ticking in a different thread, since our signal socket
		// is connected here synchronously
		CZSPAS_INFO("Dummy listen socket=%d", (int)(dummyListen.m_s));
		auto tmptick = std::async(std::launch::async, [this, &signalInConnected]
		{
			while (!signalInConnected)
				tick();
		});

		m_signalOut = std::make_unique<Socket>(*this);
		ec = reinterpret_cast<Socket*>(m_signalOut.get())->connect("127.0.0.1", dummyListen.m_localAddr.second);
		CZSPAS_ASSERT(!ec);
		CZSPAS_INFO("m_signalOut socket=%d", (int)(m_signalOut->m_s));
		tmptick.get(); // Wait for the std::async to finish

		// Initiate reading for the dummy input socket
		startSignalIn();

		details::utils::disableNagle(m_signalIn->m_s);
		details::utils::disableNagle(m_signalOut->m_s);
	}

	~Service()
	{
		CZSPAS_ASSERT(m_stopped);
		static_cast<Socket*>(m_signalOut.get())->doCancel();
		static_cast<Socket*>(m_signalIn.get())->doCancel();
		m_cmdQueue([&](CmdQueue& q)
		{
			CZSPAS_ASSERT(q.size() == 0);
		});

		// Releasing these here, instead of letting it be cleared up automatically,
		// so that Socket can do asserts that use their owner (Service) while all
		// the owner's members are all valid
		m_signalOut = nullptr;
		m_signalIn = nullptr;
	}

	static Service& getFrom(Acceptor& s)
	{
		return static_cast<Service&>(s.m_owner);
	}
	static Service& getFrom(Socket& s)
	{
		return static_cast<Service&>(s.m_owner);
	}


	// Gets commands from the command queue into the temporary command queue for processing
	bool prepareTmpQueue()
	{
		// The temporary queue might still have elements, so don't get more items if that's the case
		if (m_tmpQueue.size() == 0)
		{
			m_cmdQueue([&](CmdQueue& q)
			{
				std::swap(q, m_tmpQueue);
			});
		}
		return m_tmpQueue.size() > 0;
	}

	//! Processes whatever it needs
	// \return
	//		false : We are shutting down, and no need to call again
	//		true  : We should call tick again
	bool tick()
	{
		// put a marker on the callstack, so other code can detect when inside the tick function
		typename details::Callstack<details::ServiceData>::Context ctx(this);

		// Continue executing commands until the queue is empty
		while (prepareTmpQueue())
		{
			while (m_tmpQueue.size())
			{
				auto&& fn = m_tmpQueue.front();
				// Since we are calling unknown code (the handler), which might throw an exception,
				// we need to make sure we still remove the handler from the queue
				auto guard = details::scopeGuard([this] { m_tmpQueue.pop(); });
				if (fn)
					fn();
				else
					m_finishing = true;
			}

			if (m_finishing)
			{
				// If we are finished, then there can't be any commands left
				CZSPAS_ASSERT(m_tmpQueue.size() == 0);

				//
				// Cancel all handlers in all the sockets we have at the moment
				//
				for (auto&& s : m_connects)
				{
					addCmd([h=std::move(s.second.h)]
					{
						h(Error(Error::Code::Cancelled));
					});
				}
				m_connects.clear();

				auto cancel = [](auto&& container)
				{
					for (auto&& s : container)
						s->doCancel();
					container.clear();
				};
				cancel(m_accepts);
				cancel(m_recvs);
				cancel(m_sends);
			}
		}

		if (m_finishing)
			return false;

		if (m_connects.size() == 0 && m_accepts.size() == 0 && m_recvs.size() == 0 && m_sends.size() == 0)
			return true;

		fd_set readfds, writefds;
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		SocketHandle maxfd = 0;
		auto addSockets = [&maxfd](auto&& container, fd_set& fds)
		{
			for (auto&& s : container)
			{
				assert(s->m_s != CZSPAS_INVALID_SOCKET);
				if (s->m_s > maxfd)
					maxfd = s->m_s;
				FD_SET(s->m_s, &fds);
			}
		};
		addSockets(m_accepts, readfds);
		addSockets(m_recvs, readfds);
		addSockets(m_sends, writefds);

		// For non-blocking connects, select will let us know a connect finished through the write fds
		timeval timeout{ 0,0 };
		if (m_connects.size())
		{
			auto start = std::chrono::high_resolution_clock::now();
			std::chrono::nanoseconds t(std::numeric_limits<long long>::max());
			for (auto&& s : m_connects)
			{
				if (s.first->m_s > maxfd)
					maxfd = s.first->m_s;
				FD_SET(s.first->m_s, &writefds);
				// Calculate timeout
				std::chrono::nanoseconds remain = s.second.timeoutPoint - start;
				if (remain < t)
					t = remain;
			}

			if (t.count() > 0)
			{
				timeout.tv_sec = static_cast<long>(t.count() / (1000 * 1000 * 1000));
				timeout.tv_usec = static_cast<long>((t.count() % (1000 * 1000 * 1000)) / 1000);
			}
		}

		auto res = select(
			(int)maxfd + 1,
			&readfds,
			&writefds,
			NULL,
			(m_connects.size()) ? &timeout : NULL);

		// get current time, if we are running
		std::chrono::time_point<std::chrono::high_resolution_clock> end;
		if (m_connects.size())
			end = std::chrono::high_resolution_clock::now();

		if (res == CZSPAS_SOCKET_ERROR)
			CZSPAS_ERROR(details::ErrorWrapper().msg().c_str());

		for (auto it = m_accepts.begin(); it != m_accepts.end(); )
		{
			if (FD_ISSET((*it)->m_s, &readfds))
			{
				if ((*it)->doAccept())
					++it;
				else
					it = m_accepts.erase(it);
			}
			else
				++it;
		}

		for (auto it = m_recvs.begin(); it != m_recvs.end(); )
		{
			if (FD_ISSET((*it)->m_s, &readfds))
			{
				if ((*it)->doRecv())
					++it;
				else
					it = m_recvs.erase(it);
			}
			else
				++it;
		}

		// Check writes
		for (auto it = m_sends.begin(); it != m_sends.end(); )
		{
			if (FD_ISSET((*it)->m_s, &writefds))
			{
				if ((*it)->doSend())
					++it;
				else
					it = m_sends.erase(it);
			}
			else
				++it;
		}

		// Check the pending connects
		for (auto it = m_connects.begin(); it != m_connects.end();)
		{
			if (FD_ISSET(it->first->m_s, &writefds))
			{
				auto sock = it->first;
				// Check if we are really connected, or something else happened.
				// Windows seems to just wait for the timeout, but Linux gets here before the timeout.
				// So, we need to check if connected or if it was an error
				int result;
				socklen_t result_len = sizeof(result);
				if (getsockopt(sock->m_s, SOL_SOCKET, SO_ERROR, (char*)&result, &result_len) == -1)
				{
					CZSPAS_FATAL(details::ErrorWrapper().msg().c_str());
				}

				if (result == 0)
				{
					// #TODO : Test what happens if the getRemoteAddr fails
					sock->m_peerAddr = details::utils::getRemoteAddr(sock->m_s);
					sock->m_localAddr = details::utils::getLocalAddr(sock->m_s);
					CZSPAS_INFO("Socket %d connected to %s:%d", (int)sock->m_s, sock->m_peerAddr.first.c_str(), sock->m_peerAddr.second);
					addCmd([op=std::move(it->second)]
					{
						op.h(Error());
					});
				}
				else
				{
					auto ec = details::ErrorWrapper().getError();
					ec.code = Error::Code::ConnectFailed;
					addCmd([sock=it->first, op=std::move(it->second), ec]
					{
						sock->releaseHandle();
						op.h(ec);
					});
				}

				it = m_connects.erase(it);
			}
			else
				++it;
		}

		// Check for expired connection attempts
		for (auto it = m_connects.begin(); it != m_connects.end();)
		{
			if (it->second.timeoutPoint < end)
			{
				addCmd([sock=it->first, op=std::move(it->second)]
				{
					sock->releaseHandle();
					op.h(Error::Code::ConnectFailed);
				});
				it = m_connects.erase(it);
			}
			else
			{
				++it;
			}
		}

		return true;
	}

	void run()
	{
		while (tick())
		{
		}
	}


	//! Interrupts any tick calls in progress, and marks the service as finishing
	// You should not make any other calls to the service after this
	void stop()
	{
		m_stopped = true;
		// Signal the end by sending an "empty" command
		// NOTE:
		// Although "nullptr" would be preferable since it would convert to std::function<void()>, addCmd parameter
		// itself is not an std::function for performance reasons. So I need to pass an empty std::function
		addCmd(std::function<void()>());
	}

	template< typename H, typename = details::IsSimpleHandler<H> >
	void post(H&& handler)
	{
		addCmd(std::forward<H>(handler));
	}

	template< typename H, typename = details::IsSimpleHandler<H> >
	void dispatch(H&& handler)
	{
		if (tickingInThisThread())
			handler();
		else
			post(std::forward<H>(handler));
	}

protected:

	void startSignalIn()
	{
		Socket::RecvOp op;
		op.buf = m_signalInBuf;
		op.bufLen = sizeof(m_signalInBuf);
		op.fill = true;
		op.h = [this](const Error& ec, int bytesTransfered)
		{
			if (ec)
				return;
			CZSPAS_ASSERT(bytesTransfered == 1);
			--m_signalFlight;
			auto i = m_signalFlight.load();
			assert(m_signalFlight.load() >= 0);
			startSignalIn();
		};
		static_cast<Socket*>(m_signalIn.get())->m_recvs.push(std::move(op));
		m_recvs.insert(reinterpret_cast<Socket*>(m_signalIn.get()));
	}

};

} // namespace spas
} // namespace cz
