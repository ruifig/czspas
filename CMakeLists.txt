cmake_minimum_required(VERSION 3.5)
project(czspas)

include(cmake/ucm.cmake)
include(cmake/utils.cmake)

set_property( GLOBAL PROPERTY USE_FOLDERS ON )

# Will cause building to display what compiler parameters are being used, among other things
SET(CMAKE_VERBOSE_MAKEFILE_ON)

add_subdirectory(source)
add_subdirectory(UnitTest++)
add_subdirectory(tests)
#add_subdirectory(samples)

