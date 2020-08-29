/**
 * @brief - ethernet ids system
 * 
 * @copyright - All rights reserved 2020-present Devendra Naga (devendra.aaru@outlook.com)
 */
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <memory>
#include <fstream>
#include <condition_variable>
#include <string>
#include <functional>
#include <eth_ids.h>
#include <socket_api.h>
#include <monitor_engine.h>
#include <jsoncpp/json/json.h>
#include <event_manager.h>

#define ETH_IDS_DEV_NAME "enp0s3"

#define ETH_IDS_BASE_CONFIG_FILE "./eth_ids_config.json"

static auto_os::lib::event_manager *ev_;

namespace auto_os::middleware {

int eth_ids_config::parse()
{
    Json::Value root;
    std::ifstream config(ETH_IDS_BASE_CONFIG_FILE, std::ifstream::binary);
    config >> root;

    if (root["daq_source"] == "interface") {
        daq = daq_source::eInterface;
    } else if (root["daq_source"] == "pcap") {
        daq = daq_source::ePcap;
    } else {
        return -1;
    }
    use_all_interfaces = root["interface"]["use_all_interfaces"].asBool();
    use_interface = root["interface"]["use_interface"].asString();
    pcap_path = root["pcap"]["path"].asString();
    return 0;
}

eth_ids::eth_ids()
{
    int ret;

    ids_config_ = eth_ids_config::instance();
    ret = ids_config_->parse();
    if (ret < 0) {
        throw std::runtime_error("failed to parse ids configuration file\n");
    }

    // create monitoring engine
    e_ = std::make_unique<monitor_engine>();

    ev_ = auto_os::lib::event_manager::instance();

    if (ids_config_->daq == daq_source::eInterface) {
        r_ = std::make_unique<auto_os::lib::raw_socket>(ids_config_->use_interface, 0);
        auto rx_callback = std::bind(&eth_ids::receive_packet, this, std::placeholders::_1);
        ev_->create_socket_event(r_->get_socket(), rx_callback);
        //rx_thr_ = std::make_unique<std::thread>(&eth_ids::receive_thread, this);
    } else if (ids_config_->daq == daq_source::ePcap) {
        pcap_in_ = std::make_unique<pcap_input>(ids_config_->pcap_path);
        //replay_thr_ = std::make_unique<std::thread>(&eth_ids::replay_thread, this);
    }
}

eth_ids::~eth_ids()
{
}

void eth_ids::receive_packet(int id)
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
    if (ids_config_->daq == daq_source::eInterface) {
        //rx_thr_->join();
    } else if (ids_config_->daq == daq_source::ePcap) {
        //replay_thr_->join();
    }
    ev_->start();
}

}

int main()
{
    auto_os::middleware::eth_ids eth_ids;

    eth_ids.start();
}

