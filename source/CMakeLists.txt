cmake_minimum_required(VERSION 3.16)

set(SOURCE_FILES
	"crazygaze/spas/spas.h"
	)

source_group("crazygaze\\spas" FILES ${SOURCE_FILES})

add_library(czspas INTERFACE)
add_library(cz::spas ALIAS czspas)

target_include_directories(czspas INTERFACE "")

if (MSVC)
	target_link_libraries(czspas INTERFACE ws2_32)
elseif (MINGW)
	target_link_libraries(czspas INTERFACE ws2_32 mswsock )
elseif(CMAKE_COMPILER_IS_GNUCXX OR ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang"))
	target_link_libraries(czspas INTERFACE pthread )
endif()

# Dummy target so that header only libraries show up on the IDE
add_custom_target(czspas_ SOURCES ${SOURCE_FILES})

target_compile_features(czspas INTERFACE cxx_std_17)

