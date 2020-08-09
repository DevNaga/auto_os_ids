project(ids_daemon)

cmake_minimum_required(VERSION 3.10)

set(ETH_IDS_SRC
	./eth_ids/eth_ids.cc
	./eth_ids/monitor_engine.cc
	./eth_ids/analytics_db.cc
	./eth_ids/daq/pcap_input.cc)

include_directories(
	./eth_ids/
	./eth_ids/daq/)

add_executable(eth_ids ${ETH_IDS_SRC})
target_link_libraries(eth_ids auto_network auto_lib jsoncpp pthread)
