/**
 * @brief - implements monitor engine (contains filters for the configured json filters)
 *
 * @copyright - All rights reserved Devendra Naga (devendra.aaru@outlook.com) 2020-present
 */
#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
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

    ipv4_rules ip_rule;

    ip_rule.drop_protocol_except = root["deny"]["ipv4"]["protocol_except"].asInt();
    ip_rule.flag_invalid_ip4_csum = root["deny"]["ipv4"]["flag_invalid_checksum"].asBool();
    ip_rule.flag_subnet_class_c_broadcasts = root["deny"]["ipv4"]["flag_subnet_class_c_broadcast"].asBool();

    for (auto drop_senders : root["deny"]["ipv4"]["drop_senders"]) {
        auto d_s_addr = drop_senders.asString();
        uint32_t sender = inet_addr(d_s_addr.c_str());

        ip_rule.drop_senders.push_back(sender);
    }

    l3_rules l3_r;

    l3_r.ip_rule = std::move(ip_rule);
    rdb_.deny.l3.push_back(l3_r);
}

monitor_engine::~monitor_engine()
{
}

int monitor_engine::run_l2_rules(auto_os::network::ethernet_header *eth)
{
    for (auto l2_rules : rdb_.deny.l2) {
        for (auto ethertype : l2_rules.ethertype) {
            if (eth->ethertype == ethertype) {
                analytics_db::instance()->update_ethertype_denial(eth->ethertype, traffic_direction::in);
            }
        }
        for (auto dest_mac : l2_rules.destmac) {
            if ((eth->dest[0] == dest_mac[0]) &&
                (eth->dest[1] == dest_mac[1]) &&
                (eth->dest[2] == dest_mac[2]) &&
                (eth->dest[3] == dest_mac[3]) &&
                (eth->dest[4] == dest_mac[4]) &&
                (eth->dest[5] == dest_mac[5])) {
		        analytics_db::instance()->update_mac_denial(eth->dest, traffic_direction::in);
                return -1; // deny rule applied
            }
        }
    }

    return 0;
}

template <typename T1, typename T2>
bool operator==(T1 t1, T2 t2)
{
    return static_cast<bool>(static_cast<int>(t1) == static_cast<int>(t2));
}

void monitor_engine::process_input(packet_buffer *buf)
{
    auto_os::network::Ethernet_Layer eth_l;
    auto_os::network::ethernet_header eth_hdr;
    auto_os::network::Ipv4_Packet ipv4_l;
    auto_os::network::ipv4_header ipv4_hdr;
    int ret;
    size_t off = 0;

    ret = eth_l.Deserialize(buf->pkt, buf->pkt_size, off, &eth_hdr);
    if (ret < 0) {
        return;
    }

#if 0
    printf("src: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    eth_hdr.src[0],
                    eth_hdr.src[1],
                    eth_hdr.src[2],
                    eth_hdr.src[3],
                    eth_hdr.src[4],
                    eth_hdr.src[5]);
    printf("dest: %02x:%02x:%02x:%02x:%2x:%02x\n",
                    eth_hdr.dest[0],
                    eth_hdr.dest[1],
                    eth_hdr.dest[2],
                    eth_hdr.dest[3],
                    eth_hdr.dest[4],
                    eth_hdr.dest[5]);
    printf("ethertype %04x\n", eth_hdr.ethertype);
#endif

    //auto_os::lib::hexdump(buf->pkt, buf->pkt_size);
    ret = run_l2_rules(&eth_hdr);
    if (ret < 0) {
        return;
    }

    if (eth_hdr.ethertype == auto_os::network::ethertypes::IPV4) {
        ret = ipv4_l.Deserialize(buf->pkt, buf->pkt_size, off, &ipv4_hdr);
        if (ret < 0) {
            return;
        }

        ret = run_ipv4_rules(&ipv4_hdr);
        if (ret < 0) {
            return;
        }
    } else { // unsupportive protocol
        return;
    }
}

int monitor_engine::run_ipv4_rules(auto_os::network::ipv4_header *ipv4_hdr)
{
    ipv4_rules *ipv4_r;

    for (auto l3_rule : rdb_.deny.l3) {
        ipv4_r = &l3_rule.ip_rule;

        if (ipv4_hdr->version != ipv4_r->drop_protocol_except) {
            return -1;
        }
    }
}

}


