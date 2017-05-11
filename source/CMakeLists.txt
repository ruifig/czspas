cmake_minimum_required(VERSION 3.5)
project(spas)

ucm_add_files("crazygaze/spas/spas.h" TO SPAS_SRC)

add_library(spas INTERFACE)
target_include_directories(spas INTERFACE "")
if (MSVC)
	target_link_libraries(spas INTERFACE ws2_32)
elseif (MINGW)
	target_link_libraries(spas INTERFACE ws2_32 mswsock )
	#SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lws2_32")
elseif(CMAKE_COMPILER_IS_GNUCXX OR ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang"))
	target_link_libraries(spas INTERFACE pthread )
endif()

# Dummy target so that header only libraries show up on the IDE
add_custom_target(spas_ SOURCES ${SPAS_SRC})

