#ifndef __AUTO_NETWORK_UDP_H__
#define __AUTO_NETWORK_UDP_H__

#include <stdint.h>

namespace auto_os::network {

struct udp_header {
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

class Udp_Packet {
    public:
        explicit Udp_Packet();
        ~Udp_Packet();

        int Serialize(uint8_t *buf, size_t buf_size, size_t &off, udp_header *ipv4_h);
        int Deserialize(uint8_t *buf, size_t buf_size, size_t &off, udp_header *ipv4_h);
        void Print(udp_header *ipv4_h);
};

}

#endif


