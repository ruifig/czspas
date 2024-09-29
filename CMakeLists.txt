cmake_minimum_required(VERSION 3.16)

project(czspas
		DESCRIPTION "Minimalistic socket library inspired by Asio/Boost Asio, implemented in 1 single header file"
		LANGUAGES CXX)

option(CZSPAS_TESTS "Create projects for czspas tests" OFF)
option(CZSPAS_SAMPLES "Create projects for czspas samples" OFF)
option(CZSPAS_DOCS "Generates doxygen documentation" OFF)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

#if (NOT DEFINED CZ_IDE_FOLDER)
#	set(CZ_IDE_FOLDER "")
#endif()

add_subdirectory(./source)

if (CZSPAS_TESTS)
	# If Catch2 is found somewhere in the library's folder and cmake target doesn't exist, then we set it up.
	# This check makes it possible to reuse a Catch2 target the user already has
	if (EXISTS "${CMAKE_CURRENT_LIST_DIR}/deps/Catch2" AND NOT TARGET Catch2WithMain)
		message(STATUS "Catch2 folder found in ${PROJECT_NAME}. Defining Catch2 target")
		add_subdirectory(./deps/Catch2)
		# Set in what folder it shows up in the IDE
		set_target_properties(Catch2 PROPERTIES FOLDER "${CZ_IDE_FOLDER}/deps")
		set_target_properties(Catch2WithMain PROPERTIES FOLDER "${CZ_IDE_FOLDER}/deps")

		# Since we are adding Catch2 on our own, we can tweak some flags to make it faster to build
		if(MSVC)
			## Enable multi-core building
			target_compile_options(Catch2 PUBLIC /MP)
			target_compile_options(Catch2WithMain PUBLIC /MP)
		endif()

	endif()

	if (TARGET Catch2WithMain)
		message(STATUS "Enabling ${PROJECT_NAME} tests")
		add_subdirectory(tests)
	else()
		message(FATAL_ERROR "Requested tests, but Catch2 not found")
	endif()
endif()

if (CZSPAS_SAMPLES)
	add_subdirectory(samples)
endif()

if (CZSPAS_DOCS)
	add_subdirectory("./docs-sources")
endif()


