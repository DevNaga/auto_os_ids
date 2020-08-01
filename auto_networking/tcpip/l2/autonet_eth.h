#ifndef __AUTO_NETWORK_ETH_H__
#define __AUTO_NETWORK_ETH_H__

#include <iostream>

namespace auto_os::network {

struct ethernet_header {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t ethertype;
};

class Ethernet_Layer {
    public:
        explicit Ethernet_Layer();
        ~Ethernet_Layer();

        int Serialize(uint8_t *buf, size_t buf_size, size_t &off, ethernet_header *eth);
        int Deserialize(uint8_t *buf, size_t buf_size, size_t &off, ethernet_header *eth);
};

}

#endif


