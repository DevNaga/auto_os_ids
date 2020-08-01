project("auto_network")

cmake_minimum_required(VERSION 3.10)

set(AUTO_NET_LIB_SRC
	./tcpip/l2/autonet_eth.cc)

include_directories(
	./tcpip/l2/
	./tcpip/common/
	../auto_lib/include)

add_library(auto_network SHARED ${AUTO_NET_LIB_SRC})
target_link_libraries(auto_network auto_lib pthread)

