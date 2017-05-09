#include "testsPCH.h"
#include "UnitTest++/TestReporterStdout.h"

#define LOOP_TESTS 1

UnitTest::Timer gTimer;

namespace UnitTest
{
	class czspasTestReporter : public TestReporter
	{
		virtual void ReportFailure(TestDetails const& details, char const* failure) override
		{
			CZSPAS_DEBUG_BREAK();
			using namespace std;
#if defined(__APPLE__) || defined(__GNUG__)
			char const* const errorFormat = "%s:%d:%d: error: Failure in %s: %s\n";
			fprintf(stderr, errorFormat, details.filename, details.lineNumber, 1, details.testName, failure);
#else
			char const* const errorFormat = "%s(%d): error: Failure in %s: %s\n";
			fprintf(stderr, errorFormat, details.filename, details.lineNumber, details.testName, failure);
#endif
		}

		virtual void ReportTestStart(TestDetails const& test) override
		{
			printf("TEST START: %s\n", test.testName);
		}

		virtual void ReportTestFinish(TestDetails const& test, float) override
		{
			printf("TEST FINISH: %s\n", test.testName);
		}

		virtual void ReportSummary(int totalTestCount, int failedTestCount, int failureCount, float secondsElapsed) override
		{
			using namespace std;

			if (failureCount > 0)
				printf("FAILURE: %d out of %d tests failed (%d failures).\n", failedTestCount, totalTestCount, failureCount);
			else
				printf("Success: %d tests passed.\n", totalTestCount);

			printf("Test time: %.2f seconds.\n", secondsElapsed);
		}
	};

	int czspasRunAllTests()
	{
		czspasTestReporter reporter;
		TestRunner runner(reporter);
		return runner.RunTestsIf(Test::GetTestList(), NULL, True(), 0);
	}
} // namespace UnitTest


namespace cz
{
	namespace spas
	{
		bool MyTCPLog::ms_assertOnFatal = true;
		bool MyTCPLog::ms_logEnabled = false;

		void MyTCPLog::out(bool fatal, const char* type, const char* fmt, ...)
		{
			if (!ms_logEnabled || !fatal)
				return;
			char buf[256];
			detail::copyStrToFixedBuffer(buf, type);
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
	gTimer.Start();

	//cz::spas::MyTCPLog::ms_logEnabled = false;
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
		printf("*** Run %d ***\n", counter);
		res = UnitTest::czspasRunAllTests();
		//return res;
		if (res != 0)
			break;
	}
#else
	auto res = UnitTest::RunAllTests();
#endif

	return res == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
