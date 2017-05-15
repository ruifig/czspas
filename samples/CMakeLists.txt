cmake_minimum_required(VERSION 3.5)

ucm_add_files(
	"HelloWorld/HelloWorld.cpp"
	TO 01_SRC
	)

add_executable(HelloWorld ${01_SRC})
cz_set_postfix()
target_link_libraries(tests czspas UnitTest++)

