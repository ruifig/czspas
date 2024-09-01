cmake_minimum_required(VERSION 3.5)

set(SOURCE_FILES
	"new_tests_spas.cpp"
	"Semaphore.h"
	"targetver.h"
	"tests_spas.cpp"
	"tests_spas_helper.h"
	"testsPCH.h"
	)

add_executable(czspas_tests ${SOURCE_FILES})
target_precompile_headers(czspas_tests PUBLIC "testsPCH.h")
target_link_libraries(czspas_tests cz::spas Catch2WithMain)
set_property(TARGET czspas_tests PROPERTY FOLDER "${CZ_IDE_FOLDER}${PROJECT_NAME}/tests")
set_target_properties(czspas_tests PROPERTIES CXX_STANDARD 17)

if(MSVC)
	#target_compile_options(czspas_tests PRIVATE /Wall)
endif()

add_test(NAME czspas_tests COMMAND czspas_tests)

