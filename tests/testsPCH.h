#pragma once

#ifdef _WIN32
#include "targetver.h"
#endif

#define SHORT_TESTS 1

// If set to 1, and running on Debug and Windows, it will enable some more CRT memory debug things
#define ENABLE_MEM_DEBUG 0

namespace cz
{
	namespace spas
	{
		struct MyTCPLog
		{
			static bool ms_assertOnFatal;
			static bool ms_logEnabled;
			static void out(bool fatal, const char* type, const char* fmt, ...);
		};
	}
}

//
// These need to be defined BEFORE including spas
//
#define CZSPAS_INFO(fmt, ...) MyTCPLog::out(false, "Info: ", fmt, ##__VA_ARGS__)
#define CZSPAS_WARN(fmt, ...) MyTCPLog::out(false, "Warning: ", fmt, ##__VA_ARGS__)
#define CZSPAS_ERROR(fmt, ...) MyTCPLog::out(false, "Error: ", fmt, ##__VA_ARGS__)

#include "crazygaze/spas/spas.h"

#include <stdio.h>
#include <vector>
#include <string>
#include <queue>

#include "Semaphore.h"

//
// UnitTest++
//
#include "UnitTest++/UnitTest++.h"
#include "UnitTest++/CurrentTest.h"

