/**
 * @brief - analytics interface
 * 
 * - logging
 * - storing and forwarding over to an ip address
 *
 * @copyright - All rights reserved 2020-present Devendra Naga (devendra.aaru@outlook.com)
 */
#ifndef __AUTO_MIDDLEWARE_IDS_ANALYTICS_H__
#define __AUTO_MIDDLEWARE_IDS_ANALYTICS_H__

#include <array>

namespace auto_os::middleware {

enum class traffic_direction {
    in,
    out,
};

struct l2_mac_denials {
    std::array<uint8_t, 6> denied_mac;
    traffic_direction traf;
};

struct l2_ethertype_denials {
    uint16_t ethertype;
    traffic_direction traf;
};

struct l2_vlan_denials {
    uint16_t vlan_id;
    traffic_direction traf;
};

class analytics_db {
    public:
        ~analytics_db();

        static analytics_db *instance() {
            static analytics_db adb;

            return &adb;
        }

        int create_event_log(const std::string &filename);

        void update_mac_denial(uint8_t *denied_mac, traffic_direction dir);
        void update_vlan_ids(uint16_t vlan, traffic_direction dir);
        void update_ethertype_denial(uint16_t ethertype, traffic_direction dir);
        void report_ptp_approval(uint8_t *mac_3_bytes, traffic_direction dir);

    private:
        explicit analytics_db();
        std::vector<l2_mac_denials> l2_mac_deny_list;
        std::vector<l2_ethertype_denials> l2_ethertype_deny_list;
        std::vector<l2_vlan_denials> vlan_deny_list;
        FILE *event_fp_;
};

class analytics {
    public:
        explicit analytics();
        ~analytics();
};

}
        
#endif


