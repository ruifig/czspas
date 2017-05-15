cmake_minimum_required(VERSION 3.5)

##################################################################
ucm_add_files(
	"Echo/EchoServer.cpp"
	TO EchoServer_SRC
	)

add_executable(EchoServer ${EchoServer_SRC})
cz_set_postfix(EchoServer)
target_link_libraries(EchoServer czspas)
set_target_properties(EchoServer PROPERTIES FOLDER Samples)

##################################################################
ucm_add_files(
	"Echo/EchoClient.cpp"
	TO EchoClient_SRC
	)

add_executable(EchoClient ${EchoClient_SRC})
cz_set_postfix(EchoClient)
target_link_libraries(EchoClient czspas)
set_target_properties(EchoClient PROPERTIES FOLDER Samples)

