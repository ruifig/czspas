cmake_minimum_required(VERSION 3.5)
project(czspas)

ucm_add_files("crazygaze/spas/spas.h" TO CZSPAS_SRC)

add_library(czspas INTERFACE)
target_include_directories(czspas INTERFACE "")

# Dummy target so that header only libraries show up on the IDE
add_custom_target(czspas_ SOURCES ${CZSPAS_SRC})
