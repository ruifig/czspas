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

Version of Asion czspas was based on
	https://think-async.com/Asio/asio-1.10.6/doc/index.html

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

------------------------------------------------

Some intentional design choices:
	- Simplicity over performance
	- Limited feature set. If a bigger feature set is required, use another networking library (e.g: https://think-async.com/Asio/).
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
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <netdb.h>
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
#include <string_view>
#include <optional>

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

#if _WIN32
	#include <iphlpapi.h>

	// #RVF : Revise this and the API that retrieves these. I don't want to have something that works only for Windows
	struct NetworkAdapterInfo
	{
		struct Address
		{
			std::string str;
			bool isIPV6;
			union
			{
				IN6_ADDR ipv6;
				IN_ADDR ipv4;
			};
		};

		std::string name;
		std::wstring wname;
		std::vector<Address> unicast;
		std::vector<Address> anycast;
		std::vector<Address> multicast;
		std::vector<Address> gateways;
	};

#endif


namespace cz
{
namespace spas
{

// Forward declarations
class Acceptor;
class Socket;
class Resolver;
class Service;

#define CZSPAS_ENABLE_LOGGING 1

#if CZSPAS_ENABLE_LOGGING
	#ifndef CZSPAS_INFO
		#define CZSPAS_INFO(fmt, ...) ::cz::spas::detail::defaultLogOutput(false, "LOG: ", fmt, ##__VA_ARGS__)
	#endif
	#ifndef CZSPAS_WARN
		#define CZSPAS_WARN(fmt, ...) ::cz::spas::detail::defaultLogOutput(false, "WRN: ", fmt, ##__VA_ARGS__)
	#endif
	#ifndef CZSPAS_ERROR
		#define CZSPAS_ERROR(fmt, ...) ::cz::spas::detail::defaultLogOutput(false, "ERR: ", fmt, ##__VA_ARGS__)
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
	#define CZSPAS_FATAL(fmt, ...)                                                     \
		{                                                                              \
			::cz::spas::detail::defaultLogOutput(true, "Fatal: ", fmt, ##__VA_ARGS__); \
			CZSPAS_DEBUG_BREAK();                                                      \
			exit(1);                                                                   \
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

/**
 * Very simple string_view like class.
 *
 * The main purpose is to be used in the API, but where NULL terminated strings are required.
 * The problems this tries to solve are:
 *	- Using this in the API (vs `const char*`) self documents that it can't be null.
 *	- It can then be used directly as a NULL terminated string (passed to the OS functions), and used in logging.
 *		- **NOTE**: `std::format` can log std::string_view, but that requires a C++20 compiler, and thus 
 *	- The user can pass `const char*` and `const std::string&` and it will be converted to `zstring_view`, so it is mostly transparent.
 *	- If the user tries to use an std::string_view, it will fail to compile. That's intentionally, so that the user needs to make sure it is NULL-terminated.
 */
 class zstring_view : private std::string_view
 {
  public:
	zstring_view() : std::string_view("") {};
	zstring_view(const char* s) : std::string_view(s) {}
	zstring_view(const std::string& s) : std::string_view(s) {}

	// No conversion from std::string_view allowed.
	zstring_view(std::string_view s) = delete;
	// Catch cases where the user tries to pass a nullptr as a string to the API.
	zstring_view(std::nullptr_t) = delete;

	// By design, zstring_view holds NULL terminated strings, so automatic conversions to const char* are ok
	operator const char* () const { return data(); }
	const char* c_str() const { return data(); }
	// zstring_view IS a string_view, so we can convert automatically. The reverse is not allowed.
	operator std::string_view() const { return std::string_view{data(), size()}; }

	using std::string_view::size;
	using std::string_view::length;
	using std::string_view::data;
	using std::string_view::operator[];

	constexpr bool operator==(std::string_view other) { return std::string_view(*this) == other; }
	constexpr bool operator==(const char* other) { return std::string_view(*this) == other; }
 };

/**
 * Represents any error that can be generated by czspas. 
 * It holds the error code and an optional message string
 */
struct Error
{
	// #TODO : Revise if all error codes are being used (and used in the right places)
	enum class Code
	{
		Success,
		Aborted,
		Timeout,
		ConnectionClosed,
		InvalidSocket,
		HostNotFound,
		Other
	};

	explicit Error(Code c = Code::Success);
	Error(Code c, std::string_view msg);

	/**
	 * Returns a string representing the error.
	 * If there is a custom message (e.g, from the OS), it will return that. If not, it will return the error code as a string.
	 */
	const char* msg() const;

	/**
	 * Sets a custom error message.
	 */
	void setMsg(std::string_view msg);

	/**
	 * Checks if there is an error.
	 * Note that it returns true IF THERE IS AN ERROR, not the other way around.
	 * This makes for shorter code, such as:
	 *
	 * ```
	 * if (ec)
	 * {
	 *		// handle error
	 * }
	 * ```
	 * 
	 */
	operator bool() const
	{
		return code != Code::Success;
	}

	/** Error code */
	Code code;
private:
	std::shared_ptr<std::string> optionalMsg;
};


/**
 * \defgroup Callbacks Completion Handlers
 * @{
 */

/**
 * The handler signature for #Service::post.
 */
using PostHandler = std::function<void()>;

/**
 * The handler signature for #Socket::asyncConnect and #Acceptor::asyncAccept.
 *
 * @param ec
 *		The error code. It tells if the operation succeed or not.
 */
using ConnectHandler = std::function<void(const Error& ec)>;

/**
 * The handler signature for sending and receiving data, such as #Socket::asyncSendSome and #asyncSend.
 *
 * @param ec
 *		The error code. It tells if the operation succeed or not.
 *
 * @param transfered
 *		How many bytes were sent or received.
 */
using TransferHandler = std::function<void(const Error& ec, size_t transfered)>;

/**
 * The handler signature for #Resolver::asyncResolve.
 *
 * @param ec
 *		The error code. It tells if the operation succeed or not.
 *
 * @param ip
 *		The host's ip address.
 */
using ResolveHandler = std::function<void(const Error& ec, std::string ip)>;

/**
 * @}
 */

namespace detail
{
	/**
	 * Utility class to make sure a given chunk of code is executed no matter what when unwinding the callstack.
	 */
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
			{
				m_fun();
			}
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
	 * Creates a scoped guard, which executes a lambda when going out of scope.
	 *
	 * e.g:
	 * ```
	 * auto g1 = scopeGuard( [&] { cleanup(); } );
	 * ```
	 *
	 */
	template< class Func>
	ScopeGuard<Func> scopeGuard(Func f)
	{
		return ScopeGuard<Func>(std::move(f));
	}


	enum class ScopeGuardOnExit {};
	template <typename Func>
	inline cz::spas::detail::ScopeGuard<Func> operator+(ScopeGuardOnExit, Func&& fn)
	{
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

	/**
	 * Creates an unnamed scope guard that, whose's lambda gets executed when going out of scope.
	 * E.g:
	 * ```
	 * SCOPE_EXIT { doCleanup(); };
	 * ```
	 * 
	 */
	#define CZSPAS_SCOPE_EXIT \
		auto CZSPAS_ANONYMOUS_VARIABLE(SCOPE_EXIT_STATE) \
		= cz::spas::detail::ScopeGuardOnExit() + [&]()

	void defaultLogOutput(bool fatal, const char* type, const char* fmt, ...);

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
	template<typename H>
	using IsResolveHandler = std::enable_if_t<detail::check_signature<H, void(const Error&, std::string ip)>::value>;

#if _WIN32
	struct WSAInstance
	{
		WSAInstance();
		~WSAInstance();
	};
#endif

	struct SocketOperation;
	struct AcceptOperation;
	struct ConnectOperation;
	struct SendOperation;
	struct ReceiveOperation;

	/** Puts together an OS socket handle and some operations */
	struct SocketHelper
	{
	public:

		explicit SocketHelper(Service& owner);
		SocketHelper(const SocketHelper&) = delete;
		SocketHelper(SocketHelper&&) = delete;
		SocketHelper& operator=(const SocketHelper&) = delete;
		SocketHelper& operator=(SocketHelper&&) = delete;
		~SocketHelper();

		/** Only to be used with care, if the user wants to access the underlying socket handle */
		SocketHandle getHandle();
		Service& getService();
		void setLinger(bool enabled, unsigned short timeoutSeconds);
		// For internal use in the unit tests. DO NOT USE
		void _forceClose(bool doshutdown);

		const std::pair<std::string, int>& getLocalAddr() const;
		const std::pair<std::string, int>& getPeerAddr() const;
		bool isValid() const;
		void resolveAddrs();

		Service& owner;
		SocketHandle s = CZSPAS_INVALID_SOCKET;
		std::pair<std::string, int> localAddr;
		std::pair<std::string, int> peerAddr;

		// Only for debugging: #TODO : Add a define to have it available only on Debug build
		// NOTE: In the Operation structs, these need to be set to false in both the destructor and BEFORE calling the user handler
		//		1. Its needed in the destructor, because the operation might be destroyed without calling the user handler (e.g: Aborted)
		//		2. BEFORE calling the user handler, because from the handle the user might want to queue another operation of the same type
		std::atomic<int> pendingAccept = 0; 
		std::atomic<int> pendingConnect = 0;
		std::atomic<int> pendingSend = 0;
		std::atomic<int> pendingReceive = 0;
	};

	/** Base operation */
	struct Operation
	{
		explicit Operation(std::atomic<int>* dbgCounter);
		Operation(const Operation&) = delete;
		Operation(Operation&&) = delete;
		Operation& operator=(const Operation&) = delete;
		Operation& operator=(Operation&&) = delete;
		virtual ~Operation();

		Error ec;
		std::atomic<int>* dbgCounter = nullptr;
		void setFinished();
		virtual void callUserHandler() = 0;
	};


	/** Operation performed by the Resolver class */
	struct ResolveOperation : Operation
	{
		std::string hostname;
		std::string ip;
		ResolveHandler userHandler;
		virtual void callUserHandler() override;
	};

	/** Operation posted directly to Service */
	struct PostOperation : Operation
	{
		PostHandler userHandler;
		template<typename H>
		PostOperation(Service& io, H&& h)
			: Operation(nullptr)
			, userHandler(std::forward<H>(h))
		{
		}

		virtual void callUserHandler() override;
	};

	/** Base for socket operations (e.g: accept, connect, send, receive) */
	struct SocketOperation : public Operation
	{
		SocketHelper& owner;
		explicit SocketOperation(SocketHelper& owner, std::atomic<int>* dbgCounter);
		virtual void exec(SocketHandle fd, bool hasPOLLHUP) = 0;
	};

	/** Operation to accept a connection */
	struct AcceptOperation : public SocketOperation
	{
		ConnectHandler userHandler;
		SocketHelper& clientSock;

		template<typename H>
		AcceptOperation(SocketHelper& owner, SocketHelper& dst, H&& h)
			: SocketOperation(owner, &owner.pendingAccept)
			, clientSock(dst)
			, userHandler(std::forward<H>(h))
		{
		}

		~AcceptOperation();

		virtual void exec(SocketHandle fd, bool hasPOLLHUP) override;
		virtual void callUserHandler() override;
	};

	/** Operation to perform a connect */
	struct ConnectOperation : public SocketOperation
	{
		ConnectHandler userHandler;

		template<typename H>
		ConnectOperation(SocketHelper& owner, H&& h)
			: SocketOperation(owner, &owner.pendingConnect)
			, userHandler(std::forward<H>(h))
		{
		}

		~ConnectOperation();

		virtual void exec(SocketHandle fd, bool hasPOLLHUP) override;
		virtual void callUserHandler() override;
	};

	/** Base operation for send and receive */
	struct TransferOperation : public SocketOperation
	{
		uint8_t* buf;
		size_t bufSize;
		size_t transfered = 0;
		TransferHandler userHandler;

		template<typename H>
		TransferOperation(SocketHelper& owner, std::atomic<int>* dbgCounter, uint8_t* buf, size_t len, H&& h)
			: SocketOperation(owner, dbgCounter)
			, buf(buf)
			, bufSize(len)
			, userHandler(std::forward<H>(h))
		{
		}

		~TransferOperation();
		virtual void callUserHandler() override;
	};

	/** Operation to send data */
	struct SendOperation : public TransferOperation
	{
		template<typename H>
		SendOperation(SocketHelper& owner, const uint8_t* buf, size_t len, H&& h)
			: TransferOperation(owner, &owner.pendingSend, const_cast<uint8_t*>(buf), len, std::forward<H>(h))
		{
		}

		virtual void exec(SocketHandle fd, bool hasPOLLHUP) override;
	};


	/** Operation to receive data */
	struct ReceiveOperation : public TransferOperation
	{
		template<typename H>
		ReceiveOperation(SocketHelper& owner, uint8_t* buf, size_t len, H&& h)
			: TransferOperation(owner, &owner.pendingReceive, buf, len, std::forward<H>(h))
		{
		}

		virtual void exec(SocketHandle fd, bool hasPOLLHUP) override;
	};
		 

//////////////////////////////////////////////////////////////////////////
// Reactor interface
//////////////////////////////////////////////////////////////////////////

/**
 * This is used internally as the basis on how async sockets are implemented with BSD sockets.
 * Some details :
 * - It uses poll/WSAPoll to wait for any of the sockets to have something to do.
 */
class Reactor
{
public:

	enum EventType
	{
		Read,
		Write,
		LAST=Write
	};

	Reactor();
	Reactor(const Reactor&) = delete;
	Reactor(Reactor&&) = delete;
	Reactor& operator=(const Reactor&) = delete;
	Reactor& operator=(Reactor&&) = delete;
	~Reactor();

	// Putting this in a method, so Service can call this.
	// This is required, to make sure all Operations (the ones in Service queues, and in Reactor) are destroyed BEFORE
	// Socket instances, otherwise we can get the asserts that there are pending Operations when destroying a Socket
	void deleteOps()
	{
		m_sockData.clear();
	}

	void interrupt();
	void cancel(SocketHandle fd, std::queue<std::unique_ptr<Operation>>& dst);
	void addOperation(SocketHandle fd, EventType type, std::unique_ptr<SocketOperation> op, int timeoutMs);
	void runOnce(std::queue<std::unique_ptr<Operation>>& dst);

private:

#if _WIN32
	detail::WSAInstance m_wsaInstance;
#endif
	using Timepoint = std::chrono::time_point<std::chrono::high_resolution_clock>;

	struct OperationData
	{
		void cancel(Error::Code code, std::queue<std::unique_ptr<Operation>>& dst);
		std::unique_ptr<SocketOperation> op;
		Timepoint timeout = Timepoint::max();
	};

	struct SocketData
	{
		void cancel(Error::Code code, std::queue<std::unique_ptr<Operation>>& dst);
		OperationData ops[EventType::LAST+1];
	};

	std::mutex m_mtx;
	SocketHandle m_signalIn = CZSPAS_INVALID_SOCKET;
	SocketHandle m_signalOut = CZSPAS_INVALID_SOCKET;
	std::vector<pollfd> m_fds;
	std::unordered_map<SocketHandle, SocketData> m_sockData;

	// Read as much data as possible from the signalIn socket
	void readInterrupt();

	static void setFd(pollfd& fd, const SocketData& data, Reactor::EventType type, Timepoint& timeout);

	// Return true if the operation was left empty (e.g: executed/timed out)
	bool processEventsHelper(SocketHandle fd, OperationData& opdata, int ready, bool hasPOLLHUP, Timepoint now,
	                         std::queue<std::unique_ptr<Operation>>& dst);

	void processEvents(std::queue<std::unique_ptr<Operation>>& dst);
};

/**
 * Multiple producer, multiple consumer thread safe queue.
 */
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

	template<typename... Args>
	void emplace(Args&&... args)
	{
		std::lock_guard<std::mutex> lock(m_mtx);
		m_queue.emplace(std::forward<Args>(args)...);
		m_data_cond.notify_one();
	}

	template<typename Arg>
	void push(Arg&& item)
	{
		std::lock_guard<std::mutex> lock(m_mtx);
		m_queue.push(std::forward<Arg>(item));
		m_data_cond.notify_one();
	}

	// Retrieves an item, blocking if necessary to wait for items.
	void wait_and_pop(T& popped_item)
	{
		std::unique_lock<std::mutex> lock(m_mtx);
		m_data_cond.wait(lock, [this] { return !m_queue.empty();});
		popped_item = std::move(m_queue.front());
		m_queue.pop();
	}
};

} // namespace detail


//////////////////////////////////////////////////////////////////////////
//	Service interface
//////////////////////////////////////////////////////////////////////////


/**
 * Provides the core I/O functionality for the asynchronous operations.
 *
 * An application will typically have 1 instance.
 *
 * Thread Safety:
 *	* *Distinct object*: Safe
 *	* *Shared object*: Safe, with the exception of the #run and #reset functions.
 */
class Service
{
public:
	Service(const Service&) = delete;
	Service(Service&&) = delete;
	Service& operator=(const Service&) = delete;
	Service& operator=(Service&&) = delete;

	/**
	 * Dummy work item that when constructed causes #Service::run to not return until #Service::stop is called or the item
	 * is destroyed.
	 *
	 * An instance of this class affects all #Service::run calls for the Service it is attached to, until the instance goes out of
	 * scope.
	 * 
	 */
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
		explicit Work(Work&& other) noexcept : m_io(other.m_io)
		{
			other.m_io = nullptr;
		}

		// No need to complicate further by allowing assignment. Constructors are enough until proven otherwise.
		Work& operator=(const Work& other) = delete;

		~Work()
		{
			if (m_io)
			{
				m_io->workFinished();
			}
		}

	private:
		Service* m_io;
	};

	Service();
	~Service();

	/**
	 * Blocks until all work is finished and there are no more handlers to be dispatched, or until #stop is called.
	 *
	 * If there is work to be done, it returns immediately, unless there is a #Service::Work instance attached to this Service.<br>
	 * After #run exits, #isStopped calls will return `true` regardless of the reason that caused #run
	 * to return.
	 * Subsequent calls to #run will return immediately unless there is a prior call to #reset.
	 *
	 * @returns The number of handlers that were executed.
	 *
	 * @warning
	 * #run should be called from only on thread. Typically the application will either execute it as part of the
	 * application loop, or have 1 single network thread where it is called from.
	 *
	 */
	size_t run();

	/**
	 * Asks the Service to execute the specified handler, but without calling it from inside this function.
	 *
	 * It guarantees the handler will only be called from inside a #run call.
	 * The signature of the handler must be `void handler()`
	 *
	 * Typically, the application will use this function to "post" work to the thread that is running #run.
	 *
	 * @note This is thread safe.
	 */
	template<typename H, typename = detail::IsPostHandler<H>>
	void post(H&& h)
	{
		post(std::make_unique<detail::PostOperation>(*this, std::forward<H>(h)));
	}

	/**
	 * Signals the Service to stop. If #run is currently executing, it will return as soon as possible.
	 *
	 * A call to #stop will put the Service into the stopped status regardless if there is an ongoing #run call or if
	 * there is an existing #Service::Work instance.
	 *
	 * Subsequent calls to #run will return immediately until #reset is called.
	 *
	 * @note This is thread safe.
	 */
	void stop();

	/**
	 * Checks if the Service has been stopped, either through an explicit #stop, or due to running out of work.
	 * When a Service is stopped, calls to #run will return immediately without invoking any handlers.
	 *
	 * @note This is thread safe.
	 */
	bool isStopped() const;

	/**
	 * Resets the Service in preparation for a subsequent #run invocation.
	 *
	 * This is necessary after a call to #run returns and you wish to call #run again.
	 *
	 * @warning This function must not be called while there is an unfinished call to run().
	 */
	void reset();

private:

	size_t runReadyHandlers(std::queue<std::unique_ptr<detail::Operation>>& q);

	void workStarted();
	void workFinished();
	void cancel(SocketHandle fd);
	void post(std::unique_ptr<detail::Operation> op);
	void addReactorOperation(SocketHandle fd, detail::Reactor::EventType type, std::unique_ptr<detail::SocketOperation> op, int timeoutMs);

	friend class Acceptor;
	friend class Resolver;
	friend class Socket;
	friend class Work;
	std::mutex m_mtx;
	detail::Reactor m_reactor;
	std::queue<std::unique_ptr<detail::Operation>> m_ready;
	std::queue<std::unique_ptr<detail::Operation>> m_tmpready;
	std::atomic<bool> m_stopped{false};
	std::atomic<int> m_outstandingWork{ 0 };

	// Thread used to resolve host names
	detail::SharedQueue<std::pair<Resolver*, std::unique_ptr<detail::ResolveOperation>>> m_resolverRequests;
	std::thread m_resolverThread;
};

//////////////////////////////////////////////////////////////////////////
//	Socket interface
//////////////////////////////////////////////////////////////////////////

class Socket
{
public:
	explicit Socket(Service& service);
	Socket(const Socket&) = delete;
	Socket& operator= (const Socket&) = delete;
	Socket(Socket&&) = delete;
	Socket& operator= (Socket&&) = delete;
	~Socket();

	/**
	 * Synchronous connect
	 */
	Error connect(zstring_view ip, int port);

	/**
	 * Asynchronous connect
	 */
	void asyncConnect(zstring_view ip, int port, int timeoutMs, ConnectHandler h);

	template< typename H, typename = detail::IsConnectHandler<H> >
	void asyncConnect(zstring_view ip, int port, H&& h)
	{
		asyncConnect(ip, port, -1, std::forward<H>(h));
	}

	/**
	 * Synchronous send
	 */
	size_t sendSome(const uint8_t* buf, size_t len, int timeoutMs, Error& ec);

	size_t sendSome(const uint8_t* buf, size_t len, Error& ec)
	{
		return sendSome(buf, len, -1, ec);
	}

	/**
	 * Asynchronous send
	 */
	template< typename H, typename = detail::IsTransferHandler<H> >
	void asyncSendSome(const uint8_t* buf, size_t len, int timeoutMs, H&& h)
	{
		CZSPAS_ASSERT(len > 0);
		CZSPAS_ASSERT(m_base.isValid());
		CZSPAS_ASSERT(m_base.pendingSend.load()==0 && "There is already a pending send operation");
		auto op = std::make_unique<detail::SendOperation>(m_base, buf, len, std::forward<H>(h));
		getService().addReactorOperation(m_base.s, detail::Reactor::EventType::Write, std::move(op), timeoutMs);
	}

	template< typename H, typename = detail::IsTransferHandler<H> >
	void asyncSendSome(const uint8_t* buf, size_t len, H&& h)
	{
		asyncSendSome(buf, len, -1, std::forward<H>(h));
	}


	/**
	 * Synchronous receive
	 */
	size_t receiveSome(uint8_t* buf, size_t len, int timeoutMs, Error& ec);

	size_t receiveSome(uint8_t* buf, size_t len, Error& ec)
	{
		return receiveSome(buf, len, -1, ec);
	}

	/**
	 * Asynchronous receive
	 */
	template< typename H, typename = detail::IsTransferHandler<H> >
	void asyncReceiveSome(uint8_t* buf, size_t len, int timeoutMs, H&& h)
	{
		CZSPAS_ASSERT(len > 0);
		CZSPAS_ASSERT(m_base.isValid());
		CZSPAS_ASSERT(m_base.pendingReceive.load()==0 && "There is already a pending receive operation");
		auto op = std::make_unique<detail::ReceiveOperation>(m_base, buf, len, std::forward<H>(h));
		getService().addReactorOperation(m_base.s, detail::Reactor::EventType::Read, std::move(op), timeoutMs);
	}

	template< typename H, typename = detail::IsTransferHandler<H> >
	void asyncReceiveSome(uint8_t* buf, size_t len, H&& h)
	{
		asyncReceiveSome(buf, len, -1, std::forward<H>(h));
	}

	void cancel();
	void close();
	Service& getService();
	void setLinger(bool enabled, unsigned short timeoutSeconds);
	const std::pair<std::string, int>& getLocalAddr() const;
	const std::pair<std::string, int>& getPeerAddr() const;

	//! Only to be used with care, if the user wants to access the underlying socket handle
	SocketHandle getHandle();

	// For internal use in the unit tests. DO NOT USE
	void _forceClose(bool doshutdown);

private:
	friend Acceptor;
	detail::SocketHelper m_base;
};

//////////////////////////////////////////////////////////////////////////
//	Acceptor interface
//////////////////////////////////////////////////////////////////////////

/**
 * Accepts incoming socket connections.
 *
 * A server application can use this to wait for clients to connect.
 *
 * **Thread safety**
 *	* *Distinct object*: Safe
 *	* *Shared objects*: Unsafe
 *
 */
class Acceptor
{
public:
	explicit Acceptor(Service& service);
	Acceptor(const Acceptor&) = delete;
	Acceptor& operator= (const Acceptor&) = delete;
	Acceptor(Acceptor&&) = delete;
	Acceptor& operator= (Acceptor&&) = delete;
	~Acceptor();

	/**
	 * Starts listening for new connections.
	 *
	 * @param bindIP
	 *	Address to bind to.
	 *	A `""` or `"0.0.0.0"` will listen for incoming connections on any available network interface.
	 *	An explicit value (e.g: `"127.0.0.1"`) will only listen for connections to that specific network interface (aka: localhost).
	 *
	 * @param port
	 *	What port to listen on. If 0, the OS will pick a port from the dynamic range
	 *
	 * @param ec
	 *	If an error occurs, this contains the error.
	 *
	 * @param backlog
	 *	Size of the connection backlog.
	 *	This is only an hint to the OS. It's not guaranteed.
	 *
	 * @param reuseAddr
	 *	If true it will set the SO_REUSEADDR option on the socket.
	 *	To understand the implications of this on a specific OS, read https://stackoverflow.com/questions/14388706/socket-options-so-reuseaddr-and-so-reuseport-how-do-they-differ-do-they-mean-t
	 *
	 * @return
	 *	If the call succeeds, you can then call #Acceptor::accept or #Acceptor::asyncAccept to accept client connections.
	 *
	 */
	Error listen(zstring_view bindIP, int port, int backlog, bool reuseAddr);

	/**
	 * Starts listening for new connections on all available network interfaces.
	 *
	 * @param port
	 *	What port to listen on. If 0, the OS will pick a port from the dynamic range.
	 */
	Error listen(int port);

	/**
	 * Synchronously waits for a client to connect.
	 *
	 * You need to call #Acceptor::listen before calling this.
	 *
	 * @param sock
	 *	Socket to initialize with the new connection, if a connection is accepted.
	 *
	 * @param timeoutMs
	 *	Timeout for the operation, in milliseconds.
	 *	The default value (`-1`) means no timeout will be used, and therefore the function will block forever
	 *	waiting for a client to connect.
	 */
	Error accept(Socket& sock, int timeoutMs = -1);

	/**
	 * Asynchronously waits for a client to connect.
	 *
	 * @param sock
	 *	Socket to initialize with the new connection, if a connection is accepted.
	 *
	 * @param timeoutMs
	 *	Timeout for the operation, in milliseconds.
	 *	The default value (`-1`) means no timeout will be used, and therefore the function will block forever
	 *	waiting for a client to connect.
	 *
	 * @param h
	 *	Operation handler. This will be called from inside a #Service::run call when the operation completes (successfully or not)
	 * 
	 * @warning There can be only 1 pending asyncAccept per Acceptor instance.
	 */
	template< typename H, typename = detail::IsConnectHandler<H> >
	void asyncAccept(Socket& sock, int timeoutMs, H&& h)
	{
		CZSPAS_ASSERT(m_base.isValid());
		CZSPAS_ASSERT(!sock.m_base.isValid());
		CZSPAS_ASSERT(m_base.pendingAccept.load()==0 && "There is already a pending accept operation");
		auto op = std::make_unique<detail::AcceptOperation>(m_base, sock.m_base, std::forward<H>(h));
		getService().addReactorOperation(m_base.s, detail::Reactor::EventType::Read, std::move(op), timeoutMs);
	}

	/**
	 * Asynchronously waits for a client to connect
	 *
	 * This is the same as calling `asyncAccept(sock, -1, handler)`;
	 */
	template< typename H, typename = detail::IsConnectHandler<H> >
	void asyncAccept(Socket& sock, H&& h)
	{
		asyncAccept(sock, -1, std::forward<H>(h));
	}

	void cancel();
	void close();
	Service& getService();
	void setLinger(bool enabled, unsigned short timeout);
	const std::pair<std::string, int>& getLocalAddr() const;

	//! Only to be used with care, if the user wants to access the underlying socket handle
	SocketHandle getHandle();

	// For internal use in the unit tests. DO NOT USE
	void _forceClose(bool doshutdown);

private:
	detail::SocketHelper m_base;
};

#if 0
//////////////////////////////////////////////////////////////////////////
//	Resolver interface
//////////////////////////////////////////////////////////////////////////
class Resolver
{
public:
	Resolver(Service& service)
		: m_service(service)
	{
		m_service.startResolveThread();
		CZSPAS_INFO("Resolver %p: Constructor", this);
	}

	virtual ~Resolver()
	{
		CZSPAS_INFO("Resolver %p: Destructor start", this);
		// If we are trying to destroy the Resolver from the same thread it is using for the resolve work, then either we or the
		// developer are doing something wrong
		CZSPAS_ASSERT(m_th.get_id() != std::this_thread::get_id());
		m_requests.push(nullptr);
		if (m_th.joinable())
		{
			m_th.join();
		}
		CZSPAS_INFO("Resolver %p: Destructor end", this);
	}

	Service& getService()
	{
		return m_service;
	}

	template< typename H, typename = detail::IsResolveHandler<H> >
	void asyncResolve(zstring_view hostname, H&& h)
	{
		auto request = std::make_unique<Request>();
		request->hostname = hostname;
		request->handler = std::move(h);

		// Mark the Service as having work left to do, so a call to its run() doesn't return until we finish this resolve
		m_service.workStarted();

		m_requests.push(std::move(request));
	}

private:

	void doResolve(std::unique_ptr<detail::ResolveOperation> op)
	{
		// #RVF : Remove this
		std::this_thread::sleep_for(std::chrono::milliseconds(100));

		CZSPAS_INFO("Resolver %p: Start resolve for '%s'", this, op->hostname.c_str());

		CZSPAS_SCOPE_EXIT{ CZSPAS_INFO("Resolver %p: Finished resolving for '%s'", this, op->hostname.c_str()); };

		addrinfo hints;
		addrinfo* res = nullptr;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET; // AF_INET for IPv4, AF_INET6 for IPv6, AF_UNSPEC for either
		hints.ai_socktype = SOCK_STREAM;

		int status = getaddrinfo(op->hostname.c_str(), nullptr, &hints, &res);
		CZSPAS_SCOPE_EXIT { freeaddrinfo(res); };

		if (status == 0) // Success
		{
			CZSPAS_ASSERT(res);

			// Loop over all returned results and do a inverse lookup
			addrinfo* iter; 
			for (iter = res; iter != nullptr; iter = iter->ai_next)
			{
				// We return the first result
				sockaddr_in* ipv4 = (sockaddr_in*)iter->ai_addr;
				std::pair<std::string, int> addr = detail::utils::addrToPair(*ipv4);

				op->ec = Error::Code::Success;
				op->ip = addr.first;

				CZSPAS_INFO("Resolver %p: Resolved '%s' to '%s'", this, op->hostname.c_str(), op->c_str());
				break;
			}
		}
		else
		{
			detail::ErrorWrapper e(status);
			op->ec = Error(e.isHostNotFoundError() ? Error::Code::HostNotFound : Error::Code::Other, e.msg());
			CZSPAS_ERROR("Resolver %p: Failed to resolve '%s': '%s'", this, request->hostname.c_str(), e.msg().c_str());
		}

		m_service.post(std::move(op));

		// This needs to be after the post() call. The post call does a workStarted() call, so doing this after the post() means
		// that at no point the Service will be marked as having no work
		m_service.workFinished();
	}

	void runThread()
	{
		CZSPAS_INFO("Resolver %p: Starting resolve thread.", this);

		while(true)
		{
			std::unique_ptr<Request> request;
			m_requests.wait_and_pop(request);
			if (request)
			{
				doResolve(std::move(request));
			}
			else
			{
				// An empty request means we want to stop destroy the resolver, so lets get out of the loop
				break;
			}
		}

		CZSPAS_INFO("Resolver %p: Finished resolve thread.", this);
	}

	Service& m_service;
};

#endif


namespace detail
{
	template< typename H, typename = detail::IsTransferHandler<H> >
	void asyncSendHelper(Socket& sock, const uint8_t* buf, size_t len, int timeoutMs, const Error& ec, size_t totalDone, H&& h)
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
	void asyncReceiveHelper(Socket& sock, uint8_t* buf, size_t len, int timeoutMs, const Error& ec, size_t totalDone, H&& h)
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
void asyncSend(Socket& sock, const uint8_t* buf, size_t len, H&& h)
{
	CZSPAS_ASSERT(len > 0);
	detail::asyncSendHelper(sock, buf, len, -1, Error(), 0, std::forward<H>(h));
}

template< typename H, typename = detail::IsTransferHandler<H> >
void asyncSend(Socket& sock, const uint8_t* buf, size_t len, int timeoutMs, H&& h)
{
	CZSPAS_ASSERT(len > 0);
	detail::asyncSendHelper(sock, buf, len, timeoutMs, Error(), 0, std::forward<H>(h));
}

template< typename H, typename = detail::IsTransferHandler<H> >
void asyncReceive(Socket& sock, uint8_t* buf, size_t len, H&& h)
{
	CZSPAS_ASSERT(len > 0);
	detail::asyncReceiveHelper(sock, buf, len, -1, Error(), 0, std::forward<H>(h));
}

template< typename H, typename = detail::IsTransferHandler<H> >
void asyncReceive(Socket& sock, uint8_t* buf, size_t len, int timeoutMs, H&& h)
{
	CZSPAS_ASSERT(len > 0);
	detail::asyncReceiveHelper(sock, buf, len, timeoutMs, Error(), 0, std::forward<H>(h));
}

size_t send(Socket& sock, const uint8_t* buf, size_t len, int timeoutMs, Error& ec);
size_t send(Socket& sock, const uint8_t* buf, size_t len, Error& ec);
size_t receive(Socket& sock, uint8_t* buf, size_t len, int timeoutMs, Error& ec);
size_t receive(Socket& sock, uint8_t* buf, size_t len, Error& ec);




// Do not use these
// They are in the header so they can be tested, but they should only be used internally
namespace detail
{
	/**
	 * Given a uint32_t, it swaps the byte order.
	 * This is used internally to switch between big-endian and little-endian
	 */
	uint32_t byteSwap(uint32_t v);

	/**
	 * Represent an ipv4 address
	 */
	union IPAddress
	{
		struct
		{
			uint8_t o1;
			uint8_t o2;
			uint8_t o3;
			uint8_t o4;
		} o;

		// All the octects. Note that this is big-endian
		uint32_t all;
	};
	static_assert(sizeof(IPAddress) == sizeof(uint32_t));

	std::optional<IPAddress> strToAddr(zstring_view str);
	std::string addrToStr(const IPAddress& addr);
	inline std::string to_string(const IPAddress& addr)
	{
		return addrToStr(addr);
	}

	std::optional<std::pair<IPAddress, IPAddress>> cidrStrToAddrs(zstring_view cidr);
}


/**
 * Checks if the specified ip is in a range
 *
 * \param ip IP to check
 * \param network Network address
 * \param mask subnet mask
 * \return
 * If parsing of specified strings succeeded, it returns true/false indicating if the IP is in the range. If parsing fails it
 * returns std::nullopt
 *
 * E.g:
 * ` bool inRange = isIPInRange("192.168.0.5", "192.168.0.0", "255.255.0.0"); // Returns true`
 */
std::optional<bool> isIPInRange(zstring_view ip, zstring_view network, zstring_view mask);

/**
 * Checks if the specified ip is within a CIDR range (i.e "192.168.0.0/16")
 * \param ip IP to check
 * \param cidr CIDR range
 * \return
 * If parsing of specified strings succeeded, it returns true/false indicating if the IP is in the range. If parsing fails it
 * returns std::nullopt
 *
 * E.g:
 * ` bool inRange = isIPInRange("192.168.0.5", "192.168.0.0/16"); // Returns true`
 */
std::optional<bool> isIPInRange(zstring_view ip, zstring_view cidr);

/**
 * Checks if the given IP is a private IP address, as specified in https://en.wikipedia.org/wiki/Private_network .
 * Private IPV4 addresses fall in the following ranges:
 *     Class A : 10.0.0.0 to 10.255.255.255 , subnet mask 255.0.0.0
 *     Class B : 172.16.0.0 to 172.31.255.255, subnet mask 255.240.0.0
 *     Class C : 192.168.0.0 to 192.168.255.255, subnet mask 255.255.0.0
 *
 * /return
 * If the ip parsing succeeds, it returns true/false indicating if it is a private ip or not. If the parsing fails, it returns
 * std::nullopt
 */
std::optional<bool> isPrivateIP(zstring_view ip);

#if _WIN32
std::vector<NetworkAdapterInfo> getAdaptersAddresses(bool onlyStatusUp, bool includeIPV6);
#endif

} // namespace spas
} // namespace cz

