#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <memory>
#include <fstream>
#include <condition_variable>
#include <string>
#include <eth_ids.h>
#include <socket_api.h>
#include <monitor_engine.h>
#include <jsoncpp/json/json.h>

#define ETH_IDS_DEV_NAME "enp0s3"

#define ETH_IDS_BASE_CONFIG_FILE "./eth_ids_config.json"

namespace auto_os::middleware {

eth_ids::eth_ids()
{
    Json::Value root;
    std::ifstream config(ETH_IDS_BASE_CONFIG_FILE, std::ifstream::binary);
    config >> root;

    if (root["daq_source"] == "interface") {
        ids_data_.daq = daq_source::eInterface;
    } else if (root["daq_source"] == "pcap") {
        ids_data_.daq = daq_source::ePcap;
    } else {
        throw std::runtime_error("invalid daq source");
    }

    ids_data_.use_all_interfaces = root["interface"]["use_all_interfaces"].asBool();
    ids_data_.use_interface = root["interface"]["use_interface"].asString();
    ids_data_.pcap_path = root["pcap"]["path"].asString();

    // create monitoring engine
    e_ = std::make_unique<monitor_engine>();

    if (ids_data_.daq == daq_source::eInterface) {
        r_ = std::make_unique<auto_os::lib::raw_socket>(ETH_IDS_DEV_NAME, 0);
        rx_thr_ = std::make_unique<std::thread>(&eth_ids::receive_thread, this);
    } else if (ids_data_.daq == daq_source::ePcap) {
        pcap_in_ = std::make_unique<pcap_input>(TEST_PCAP_FILE_NAME);
        replay_thr_ = std::make_unique<std::thread>(&eth_ids::replay_thread, this);
    }
}

eth_ids::~eth_ids()
{
}

void eth_ids::receive_thread()
{
    packet_buffer buf;
    int sock = r_->get_socket();
    int ret;

    while (1) {
        uint8_t from[6];
        uint16_t ethertype = 0;

        ret = r_->recv_msg(from, buf.pkt, sizeof(buf.pkt));
        if (ret < 0) {
            continue;
        }

        buf.pkt_size = ret;
        e_->process_input(&buf);
    }
}

void eth_ids::replay_thread()
{
    packet_buffer buf;
    int ret;

    while (1) {
        auto_os::lib::pcap_rechdr_t rechdr;

        ret = pcap_in_->read_record(&rechdr, buf.pkt, sizeof(buf.pkt));
        if (ret < 0) {
            break;
        }

        buf.pkt_size = ret;
        e_->process_input(&buf);
    }
}

void eth_ids::start()
{
    if (ids_data_.daq == daq_source::eInterface) {
        rx_thr_->join();
    } else if (ids_data_.daq == daq_source::ePcap) {
        replay_thr_->join();
    }
}

}

int main()
{
    auto_os::middleware::eth_ids eth_ids;

    eth_ids.start();
}

