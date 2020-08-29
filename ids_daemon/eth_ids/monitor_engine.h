#ifndef __AUTO_MIDDLEWARE_MON_ENGINE_H__
#define __AUTO_MIDDLEWARE_MON_ENGINE_H__

#include <mutex>
#include <condition_variable>

#include <autonet_eth.h>
#include <eth_ids_config.h>
#include <autonet_tcp.h>
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
    bool ptp_mac;
    std::vector<l2_rules> l2;
    std::vector<l3_rules> l3;
};

struct icmp_rules {
    bool deny;
    std::vector<std::string> deny_ips;
};

struct deny_rules {
    std::vector<l2_rules> l2;
    std::vector<l3_rules> l3;
    icmp_rules icmp_r;
};

struct rule_database {
    std::string interface;
    allow_rules allow;
    deny_rules deny;
};

enum class connection_state {
    Ack_Established,
    Closed,
};

struct tcp_conn_tracking {
    uint32_t src_ipaddr;
    uint32_t dest_ipaddr;
    uint32_t src_port;
    uint32_t dest_port;
    // is the connection initiated by the source
    bool conn_from_host;
    connection_state state;
};

class connection_tracker {
    public:
        static connection_tracker *instance() {
            static connection_tracker ct;
            return &ct;
        }

        ~connection_tracker() = default;
        connection_tracker(const connection_tracker &) = delete;
        const connection_tracker &operator=(const connection_tracker &) = delete;

        void connection_tracker_update(auto_os::network::tcp_header *tcp_h,
                                       auto_os::network::ipv4_header *ipv4_h);

    private:
        explicit connection_tracker() = default;
        std::vector<tcp_conn_tracking> conn_table_;
        std::mutex tracker_lock_;
};

class monitor_engine {
    public:
        explicit monitor_engine();
        ~monitor_engine();

        void process_input(packet_buffer *buf);

    private:
        rule_database rdb_;
        int run_l2_rules(auto_os::network::ethernet_header *eth);
        int run_vlan_rules(auto_os::network::ieee_8021q_vlan *vlan);
        int run_l3_rules(auto_os::network::ipv4_header *ipv4);
        int run_ipv4_rules(auto_os::network::ipv4_header *ipv4);
};

}

#endif


