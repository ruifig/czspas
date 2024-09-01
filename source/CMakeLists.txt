cmake_minimum_required(VERSION 3.16)

set(SOURCE_FILES
	"crazygaze/spas/spas.cpp"
	"crazygaze/spas/spas.h"
	)

set(DOC_FILES
	"../docs/API.md"
	"../docs/Examples.md"
	"../docs/Readme.md"
)

set(README_FILE
	"../readme.md"
)

source_group("crazygaze\\spas" FILES ${SOURCE_FILES})
source_group("docs" FILES ${DOC_FILES})
source_group("" FILES ${README_FILE})

add_library(czspas STATIC
	${SOURCE_FILES}
	${DOC_FILES}
	#${README_FILE}
)
target_include_directories(czspas PUBLIC "")
set_target_properties(czspas PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(czspas PROPERTIES CXX_STANDARD 17)
set_target_properties(czspas PROPERTIES FOLDER "czspas")

if (MSVC)
	target_link_libraries(czspas INTERFACE ws2_32)
	target_link_libraries(czspas INTERFACE Iphlpapi.lib)
	#target_compile_options(czspas PRIVATE /Wall)
elseif (MINGW)
	target_link_libraries(czspas INTERFACE ws2_32 mswsock )
elseif(CMAKE_COMPILER_IS_GNUCXX OR ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang"))
	target_link_libraries(czspas INTERFACE pthread )
endif()

add_library(cz::spas ALIAS czspas)

