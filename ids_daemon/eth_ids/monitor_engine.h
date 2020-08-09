#ifndef __AUTO_MIDDLEWARE_MON_ENGINE_H__
#define __AUTO_MIDDLEWARE_MON_ENGINE_H__

#include <autonet_eth.h>
#include <autonet_ipv4.h>

namespace auto_os::middleware {

struct packet_buffer {
    uint8_t pkt[10204];
    size_t pkt_size;
};

struct l2_rules {
    std::vector<std::array<uint8_t, 6>> destmac;
    std::vector<uint16_t> ethertype;
    std::vector<uint16_t> vlan_ids;
};

struct ipv4_rules {
    int drop_protocol_except;
    bool flag_invalid_ip4_csum;
    bool flag_subnet_class_c_broadcasts;
    std::vector<uint32_t> drop_senders;
};

struct l3_rules {
    ipv4_rules ip_rule;
};

struct allow_rules {
    std::vector<l2_rules> l2;
    std::vector<l3_rules> l3;
};

struct deny_rules {
    std::vector<l2_rules> l2;
    std::vector<l3_rules> l3;
};

struct rule_database {
    std::string interface;
    allow_rules allow;
    deny_rules deny;
};

class monitor_engine {
    public:
        explicit monitor_engine();
        ~monitor_engine();

        void process_input(packet_buffer *buf);

    private:
        rule_database rdb_;
        int run_l2_rules(auto_os::network::ethernet_header *eth);
        int run_l3_rules(auto_os::network::ipv4_header *ipv4);
        int run_ipv4_rules(auto_os::network::ipv4_header *ipv4);
};

}

#endif


