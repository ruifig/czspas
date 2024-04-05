#pragma once

#ifdef _WIN32
#include "targetver.h"
#endif

// If set to 1, and running on Debug and Windows, it will enable some more CRT memory debug things
#define ENABLE_MEM_DEBUG 0

#include "crazygaze/spas/spas.h"

#include <stdio.h>
#include <vector>
#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <chrono>

#include "Semaphore.h"

#include <catch2/catch_all.hpp>

using namespace std::literals::chrono_literals;

