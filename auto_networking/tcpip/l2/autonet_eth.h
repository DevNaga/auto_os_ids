#ifndef __AUTO_NETWORK_ETH_H__
#define __AUTO_NETWORK_ETH_H__

#include <iostream>
#include <autonet_ethertypes.h>

namespace auto_os::network {

enum class ieee_8021q_vlan_priority {
};

struct ieee_8021q_vlan {
};

struct ethernet_header {
    uint8_t dest[6];
    uint8_t src[6];
    // if ethertype == 0x8100 -> parse VLAN
    uint16_t ethertype;
};

class Ieee8021q_Vlan {
    public:
        explicit Ieee8021q_Vlan();
        ~Ieee8021q_Vlan();

        int Serialize(uint8_t *buf, size_t buf_size, size_t &off, ieee_8021q_vlan *vlan);
        int Deserialize(uint8_t *buf, size_t buf_size, size_t &off, ieee_8021q_vlan *vlan);
};

class Ethernet_Layer {
    public:
        explicit Ethernet_Layer();
        ~Ethernet_Layer();

        int Serialize(uint8_t *buf, size_t buf_size, size_t &off, ethernet_header *eth);
        int Deserialize(uint8_t *buf, size_t buf_size, size_t &off, ethernet_header *eth);
        void Pretty_Print();
};

}

#endif


