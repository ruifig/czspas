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
	"Echo/EchoAsynchronousClient.cpp"
	TO EchoAsynchronousClient_SRC
	)

add_executable(EchoAsynchronousClient ${EchoAsynchronousClient_SRC})
cz_set_postfix(EchoAsynchronousClient)
target_link_libraries(EchoAsynchronousClient czspas)
set_target_properties(EchoAsynchronousClient PROPERTIES FOLDER Samples)

##################################################################
ucm_add_files(
	"Echo/EchoSynchronousClient.cpp"
	TO EchoSynchronousClient_SRC
	)

add_executable(EchoSynchronousClient ${EchoSynchronousClient_SRC})
cz_set_postfix(EchoSynchronousClient)
target_link_libraries(EchoSynchronousClient czspas)
set_target_properties(EchoSynchronousClient PROPERTIES FOLDER Samples)

