cmake_minimum_required(VERSION 3.26)

#
# This file setups up the CMake targets that generates documentation.
# By default it is disabled, and can be controlled with the CZSPAS_DOCS cmake option
#
# The following needs to be installed to generate the documentation:
# * Doxygen : https://www.doxygen.nl/
# * Graphviz : https://graphviz.org/
#
#
# For understanding how this script works see:
# https://cmake.org/cmake/help/latest/module/FindDoxygen.html
#

# If we don't want to generate the docs, then skip everything in this file
if (NOT CZSPAS_DOCS)
	return()
endif()

find_package(Doxygen
	REQUIRED dot)

# Check if doxygen is installed
if (NOT DOXYGEN_FOUND)
	message(FATAL_ERROR "CZSPAS_DOCS was set, but Doxygen was not found.") 
endif()


# Where are the headers to process
#set (PUBLIC_HEADERS_PATH "${CMAKE_SOURCE_DIR}/SDK/Include")
set (PUBLIC_HEADERS_PATH "${CMAKE_SOURCE_DIR}/source")

#
# See https://www.doxygen.nl/manual/config.html to understand what these mean
#
set(DOXYGEN_PROJECT_NAME "czspas")
set(DOXYGEN_PROJECT_BRIEF "Crazygaze's (S)mall (P)ortable (A)synchronous (S)ockets)")
set(DOXYGEN_PROJECT_LOGO "./images/crazygaze.jpg")
set(DOXYGEN_PROJECT_ICON "./images/crazygaze.ico")
set(DOXYGEN_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/docs")
set(DOXYGEN_CREATE_SUBDIRS NO)
set(DOXYGEN_RECURSIVE YES)
set(DOXYGEN_USE_MDFILE_AS_MAINPAGE "pages/Main.md")
set(DOXYGEN_HTML_HEADER "doxygen-custom/header.html")
set(DOXYGEN_OPTIMIZE_OUTPUT_FOR_C YES)
set(DOXYGEN_VERBATIM_HEADERS NO)
set(DOXYGEN_SHOW_HEADERFILE NO)
set(DOXYGEN_SHOW_INCLUDE_FILES NO)
set(DOXYGEN_GENERATE_TREEVIEW YES)
set(DOXYGEN_JAVADOC_AUTOBRIEF YES)
set(DOXYGEN_SHOW_NAMESPACES NO)

set(DOXYGEN_ENABLE_PREPROCESSING YES)
set(DOXYGEN_MACRO_EXPANSION YES)
set(DOXYGEN_PREDEFINED
	"DOXYGEN_SHOULD_SKIP_THIS"
)

set(DOXYGEN_EXTRACT_ALL NO)
set(DOXYGEN_EXTRACT_PRIVATE NO)
set(DOXYGEN_EXTRACT_STATIC NO)
set(DOXYGEN_EXCLUDE_SYMBOLS
	"cz::spas::detail::*"
)

set(DOXYGEN_EXAMPLE_PATH "${CMAKE_SOURCE_DIR}/samples")

set(DOXYGEN_HIDE_UNDOC_MEMBERS YES)
set(DOXYGEN_HIDE_UNDOC_CLASSES YES)
set(DOXYGEN_HIDE_FRIEND_COMPOUNDS YES)
set(DOXYGEN_HIDE_IN_BODY_DOCS YES)

# If the HIDE_SCOPE_NAMES tag is set to NO then Doxygen will show members with their full class and namespace scopes in the documentation. If set to YES, the scope will be hidden.
set(DOXYGEN_HIDE_SCOPE_NAMES YES)

#set(DOXYGEN_DISABLE_INDEX YES)

set(DOXYGEN_INCLUDE_PATH "${PUBLIC_HEADERS_PATH}")

# [===[
# Requirements for the custom stype
set(DOXYGEN_HTML_COLORSTYLE LIGHT)
set(DOXYGEN_LAYOUT_FILE custom_layout.xml)
set(DOXYGEN_HTML_EXTRA_STYLESHEET
    doxygen-awesome.css
	doxygen-custom/custom.css
	doxygen-awesome-sidebar-only.css
	doxygen-awesome-sidebar-only-darkmode-toggle.css
	doxygen-custom/custom-alternative.css
	styles/crazygaze-styles.css
)

set(DOXYGEN_HTML_EXTRA_FILES
	doxygen-awesome-darkmode-toggle.js
	doxygen-awesome-fragment-copy-button.js
	doxygen-awesome-paragraph-link.js
	doxygen-custom/toggle-alternative-theme.js
	doxygen-awesome-interactive-toc.js
	doxygen-awesome-tabs.js
)
#]===]

set(DOXYGEN_FILE_PATTERNS
	"*.h"
	"*.md"
)

#set(DOXYGEN_ )

set(ALL_FILES
	"pages/Main.md"
	"pages/Examples.md"
	"pages/API.md"
)

source_group(
	TREE "${CMAKE_CURRENT_LIST_DIR}"
	PREFIX ""
	FILES ${ALL_FILES}
)

doxygen_add_docs(czspas_docs
	${ALL_FILES}
	"${PUBLIC_HEADERS_PATH}"
	ALL
	)
set_target_properties(czspas_docs PROPERTIES FOLDER "czspas")


