cmake_minimum_required(VERSION 3.5)

set(SOURCE_FILES
	"tests.cpp"
	"tests_spas.cpp"
	"Semaphore.h"
	"testsPCH.h"
	)

add_executable(czspas_tests ${SOURCE_FILES})
target_precompile_headers(czspas_tests PUBLIC "testsPCH.h")
target_link_libraries(czspas_tests czspas UnitTest++)
set_property(TARGET czspas_tests PROPERTY FOLDER "unit tests/czspas")

