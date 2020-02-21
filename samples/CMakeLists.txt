cmake_minimum_required(VERSION 3.16)

##################################################################
# EchoServer
##################################################################

set(ECHOSERVER_SOURCE_FILES
		"Echo/EchoServer.cpp"
   )

add_executable(czspas_sample_EchoServer ${SOURCE_FILES})
target_link_libraries(czspas_sample_EchoServer cz::spas)
set_target_properties(czspas_sample_EchoServer PROPERTIES
		FOLDER "samples/czspas samples"
		LINKER_LANGUAGE CXX
		)

##################################################################
# Echo asynchronous client
##################################################################
set(ECHOASYNCCLIENT_SOURCE_FILES
	"Echo/EchoAsynchronousClient.cpp"
	)

add_executable(czspas_sample_EchoAsyncClient ${ECHOASYNCCLIENT_SOURCE_FILES})
target_link_libraries(czspas_sample_EchoAsyncClient cz::spas)
set_target_properties(czspas_sample_EchoAsyncClient PROPERTIES
		FOLDER "samples/czspas samples"
		LINKER_LANGUAGE CXX
		)

##################################################################
# Echo synchronous client
##################################################################
set(ECHOSYNCCLIENT_SOURCE_FILES
	"Echo/EchoSynchronousClient.cpp"
	)

add_executable(czspas_sample_EchoSyncClient ${ECHOSYNCCLIENT_SOURCE_FILES})
target_link_libraries(czspas_sample_EchoSyncClient cz::spas)
set_target_properties(czspas_sample_EchoSyncClient PROPERTIES
		FOLDER "samples/czspas samples"
		LINKER_LANGUAGE CXX
		)

