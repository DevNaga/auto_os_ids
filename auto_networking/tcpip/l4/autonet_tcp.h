#ifndef __AUTONET_TCP_H__
#define __AUTONET_TCP_H__

#include <stdint.h>

namespace auto_os::network {

struct tcp_header {
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t seq_no;
    uint32_t ack_no;
    uint8_t data_offset;
    uint8_t reserved;
    uint8_t ns;
    uint8_t cwr;
    uint8_t ece;
    uint8_t urg;
    uint8_t ack;
    uint8_t psh;
    uint8_t rst;
    uint8_t syn;
    uint8_t fin;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urg_pointer;
};

class Tcp_Layer {
    public:
        explicit Tcp_Layer() = default;
        ~Tcp_Layer() = default;

        int Serialize(uint8_t *buf, size_t buf_size, size_t &off, tcp_header *tcp_h);
        int Deserialize(uint8_t *buf, size_t buf_size, size_t &off, tcp_header *tcp_h);
        void Print(tcp_header *tcp_h);
};

}

#endif

