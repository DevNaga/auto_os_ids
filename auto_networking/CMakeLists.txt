project("auto_network")

cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_FLAGS "-DCONFIG_USE_VERBOSE_PRINT")
set(CMAKE_C_FLAGS "-DCONFIG_USE_VERBOSE_PRINT")

set(AUTO_NET_LIB_SRC
	./tcpip/l2/autonet_eth.cc
	./tcpip/l2/autonet_arp.cc
	./tcpip/l3/autonet_ipv4.cc
	./tcpip/l4/autonet_icmp.cc
	./tcpip/l4/autonet_udp.cc
	./tcpip/l4/autonet_tcp.cc)

include_directories(
	./tcpip/l2/
	./tcpip/l3/
	./tcpip/l4/
	./tcpip/common/
	../auto_lib/include/)

add_library(auto_network SHARED ${AUTO_NET_LIB_SRC})
target_link_libraries(auto_network auto_lib pthread)

