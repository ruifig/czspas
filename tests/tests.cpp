#include "testsPCH.h"


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
