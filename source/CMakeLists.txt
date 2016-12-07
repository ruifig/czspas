cmake_minimum_required(VERSION 3.5)
project(czspas)

ucm_add_files("crazygaze/spas/spas.h" TO CZSPAS_SRC)

add_library(czspas INTERFACE)
target_include_directories(czspas INTERFACE "")
if (MSVC)
	target_link_libraries(czspas INTERFACE ws2_32)
elseif (MINGW)
	target_link_libraries(czspas INTERFACE ws2_32 mswsock )
	#SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lws2_32")
elseif(CMAKE_COMPILER_IS_GNUCXX OR ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang"))
	target_link_libraries(czspas INTERFACE pthread )
endif()

# Dummy target so that header only libraries show up on the IDE
add_custom_target(czspas_ SOURCES ${CZSPAS_SRC})
