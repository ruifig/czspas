cmake_minimum_required(VERSION 3.16)

##################################################################
# EchoServer
##################################################################


add_executable(czspas_sample_EchoServer
		"Echo/EchoServer.cpp")
target_link_libraries(czspas_sample_EchoServer cz::spas)
set_target_properties(czspas_sample_EchoServer PROPERTIES
		FOLDER "samples/czspas samples"
		LINKER_LANGUAGE CXX
		)

##################################################################
# Echo asynchronous client
##################################################################
add_executable(czspas_sample_EchoAsyncClient
	"Echo/EchoAsynchronousClient.cpp")
target_link_libraries(czspas_sample_EchoAsyncClient cz::spas)
set_target_properties(czspas_sample_EchoAsyncClient PROPERTIES
		FOLDER "samples/czspas samples"
		LINKER_LANGUAGE CXX
		)

##################################################################
# Echo synchronous client
##################################################################
add_executable(czspas_sample_EchoSyncClient
	"Echo/EchoSynchronousClient.cpp")
target_link_libraries(czspas_sample_EchoSyncClient cz::spas)
set_target_properties(czspas_sample_EchoSyncClient PROPERTIES
		FOLDER "samples/czspas samples"
		LINKER_LANGUAGE CXX
		)

