cmake_minimum_required(VERSION 3.16)

function(setup_czspas_sample target_name)
	add_executable(${target_name} ${ARGN})
	#target_precompile_headers(${target_name} PUBLIC "${target_name}PCH.h")
	target_link_libraries(${target_name} cz::spas)
	set_target_properties(${target_name} PROPERTIES
			FOLDER "${PROJECT_NAME}/samples"
			LINKER_LANGUAGE CXX
			)
endfunction()

setup_czspas_sample(czrpc_sample_EchoServer
		"Echo/EchoServer.cpp")
setup_czspas_sample(czrpc_sample_EchoAsyncClient
	"Echo/EchoAsynchronousClient.cpp")
setup_czspas_sample(czrpc_sample_EchoSyncClient
	"Echo/EchoSynchronousClient.cpp")

