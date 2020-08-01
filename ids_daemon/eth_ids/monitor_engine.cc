#include <iostream>
#include <fstream>
#include <vector>
#include <array>
#include <monitor_engine.h>
#include <analytics.h>
#include <autonet_eth.h>
#include <helpers.h>
#include <jsoncpp/json/json.h>

namespace auto_os::middleware {

#define RULE_FILE "./eth_ids_rules.json"

monitor_engine::monitor_engine()
{
    Json::Value root;
    std::ifstream config(RULE_FILE, std::ifstream::binary);
    config >> root;

    rdb_.interface = root["interface"].asString();

    auto l2_macaddr_rules = root["deny"]["l2_mac_addr_list"];

    std::vector<l2_rules> l2;
    l2_rules l2_i;
    int i = 0;

    // parse l2_macaddr_list
    for (auto mac : l2_macaddr_rules) {
        auto m1 = mac.asString();
        uint32_t macaddr[6];
        std::array<uint8_t, 6> mac8;

        sscanf(m1.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
                    &macaddr[0], &macaddr[1],
                    &macaddr[2], &macaddr[3],
                    &macaddr[4], &macaddr[5]);

        mac8[0] = macaddr[0];
        mac8[1] = macaddr[1];
        mac8[2] = macaddr[2];
        mac8[3] = macaddr[3];
        mac8[4] = macaddr[4];
        mac8[5] = macaddr[5];

        printf("destmac %02x:%02x:%02x:%02x:%02x:%02x\n",
                               mac8[0], mac8[1],
                               mac8[2], mac8[3],
                               mac8[4], mac8[5]);

        l2_i.destmac.push_back(mac8);
    }

    auto ethertypes = root["deny"]["ethertypes"];

    for (auto ethertype : ethertypes) {
        auto eth = ethertype.asString();
        int ethertype_elem;

        sscanf(eth.c_str(), "0x%x", &ethertype_elem);
        l2_i.ethertype.push_back(static_cast<int>(ethertype_elem));
    }

    rdb_.deny.l2.push_back(l2_i);
}

monitor_engine::~monitor_engine()
{
}

int monitor_engine::run_l2_rules(auto_os::network::ethernet_header *eth)
{
    for (auto l2_rules : rdb_.deny.l2) {
        for (auto dest_mac : l2_rules.destmac) {
            if ((eth->dest[0] == dest_mac[0]) &&
                (eth->dest[1] == dest_mac[1]) &&
                (eth->dest[2] == dest_mac[2]) &&
                (eth->dest[3] == dest_mac[3]) &&
                (eth->dest[4] == dest_mac[4]) &&
                (eth->dest[5] == dest_mac[5])) {
		analytics_db::instance()->update_mac_denial(eth->dest, traffic_direction::in);
            }
        }
    }
}

void monitor_engine::process_input(packet_buffer *buf)
{
    auto_os::network::Ethernet_Layer eth_l;
    auto_os::network::ethernet_header eth_hdr;
    int ret;
    size_t off = 0;

    ret = eth_l.Deserialize(buf->pkt, buf->pkt_size, off, &eth_hdr);
    if (ret < 0) {
        return;
    }

    //auto_os::lib::hexdump(buf->pkt, buf->pkt_size);
    ret = run_l2_rules(&eth_hdr);
    if (ret < 0) {
        return;
    }
}

}


