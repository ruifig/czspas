cmake_minimum_required(VERSION 3.16)

project(czspas
		DESCRIPTION "Minimalistic socket library inspired by Asio/Boost Asio, implemented in 1 single header file"
		LANGUAGES CXX)

option(CZSPAS_Tests "Create projects for czspas tests" OFF)
option(CZSPAS_Samples "Create projects for czspas samples" OFF)

add_subdirectory(source)

if (CZSPAS_Tests)
	# If we have a unittest-cpp folder but the parent project didn't add UnitTest++, then automatically
	# define the UnitTest++ target
	if (EXISTS "${CMAKE_CURRENT_LIST_DIR}/unittest-cpp" AND NOT TARGET UnitTest++)
		message("unittest-cpp folder found in ${PROJECT_NAME}. Adding UnitTest++ target")
		add_subdirectory(unittest-cpp)
	endif()

	if (TARGET UnitTest++)
		message("Enabling ${PROJECT_NAME} tests")
		add_subdirectory(tests)
	endif()
endif()

if (CZSPAS_Samples)
	add_subdirectory(samples)
endif()
