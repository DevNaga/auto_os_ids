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

class analytics_db {
    public:
        ~analytics_db() = default;

        static analytics_db *instance() {
            static analytics_db adb;

            return &adb;
        }

        void update_mac_denial(uint8_t *denied_mac, traffic_direction dir);
        void update_ethertype_denial(uint16_t ethertype, traffic_direction dir);

    private:
        explicit analytics_db() = default;
        std::vector<l2_mac_denials> l2_mac_deny_list;
        std::vector<l2_ethertype_denials> l2_ethertype_deny_list;
};

class analytics {
    public:
        explicit analytics();
        ~analytics();
};

}
        
#endif


