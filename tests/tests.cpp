#include "testsPCH.h"

#define LOOP_TESTS 1

namespace cz
{
	namespace spas
	{
		bool MyTCPLog::ms_assertOnFatal = true;
		bool MyTCPLog::ms_logEnabled = false;

		void MyTCPLog::out(bool fatal, const char* type, const char* fmt, ...)
		{
			if (!ms_logEnabled && !fatal)
				return;
			char buf[256];
			copyStrToFixedBuffer(buf, type);
			va_list args;
			va_start(args, fmt);
			vsnprintf(buf + strlen(buf), sizeof(buf) - strlen(buf) - 1, fmt, args);
			va_end(args);
			printf("%s\n", buf);
			if (fatal && ms_assertOnFatal)
			{
				CZSPAS_DEBUG_BREAK();
				exit(1);
			}
		}
	}
}

int main()
{
#if defined(_WIN32) && !defined(NDEBUG) && ENABLE_MEM_DEBUG
	_CrtSetDbgFlag(
		_CRTDBG_ALLOC_MEM_DF
		//| _CRTDBG_DELAY_FREE_MEM_DF
		//| _CRTDBG_CHECK_ALWAYS_DF
		| _CRTDBG_CHECK_EVERY_128_DF
	);
#endif

#if LOOP_TESTS
	int res;
	int counter = 0;
	while (true)
	{
		counter++;
		printf("Run %d\n", counter);
		res = UnitTest::RunAllTests();
		//return res;
		if (res != 0)
			break;
	}
#else
	auto res = UnitTest::RunAllTests();
#endif

	return res == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
