#ifndef __AUTONET_ICMP_H__
#define __AUTONET_ICMP_H__

#include <stdint.h>

namespace auto_os::network {

#define ICMP_TYPE_ECHO_REPLY                0
#define ICMP_TYPE_DESTINATION_UNREACHABLE   3
#define ICMP_TYPE_SOURCE_QUENCH             4
#define ICMP_TYPE_REDIRECT_MESSAGE          5
#define ICMP_TYPE_ECHO_REQUEST              8
#define ICMP_TYPE_ROUTER_ADVERTISEMENT      9
#define ICMP_TYPE_ROUTER_SOLICITATION       10
#define ICMP_TYPE_TIME_EXCEEDED             11
#define ICMP_TYPE_PARAMETER_PROBLEM         12
#define ICMP_TYPE_TIMESTAMP                 13
#define ICMP_TYPE_TIMESTAMP_REPLY           14
#define ICMP_TYPE_INFORMATION_REQUEST       15
#define ICMP_TYPE_INFORMATION_REPLY         16
#define ICMP_TYPE_ADDRESS_MASK_REQUEST      17
#define ICMP_TYPE_ADDRESS_MASK_REPLY        18
#define ICMP_TYPE_TRCEROUTE                 30
#define ICMP_TYPE_EXTENDED_ECHO_REQUEST     42
#define ICMP_TYPE_EXTENDED_ECHO_REPLY       43

struct icmp_timestamp {
    uint16_t identifier;
    uint16_t seq_no;
    uint32_t originate_timestamp;
    uint32_t receive_timestamp;
    uint32_t transmit_timestamp;
};

typedef icmp_timestamp icmp_timestamp_reply;

struct icmp_echo_request {
    uint16_t identifier; // session for ex
    uint16_t seq_no; // incremented for each new echo request
};

typedef icmp_echo_request icmp_echo_reply;

struct icmp_header {
    uint8_t type; // 1 byte
    uint8_t code; // 1 byte
    uint16_t checksum; // 2 bytes
    union {
        icmp_echo_request echo_req;
        icmp_echo_reply echo_rep;
        icmp_timestamp tstamp;
        icmp_timestamp_reply tstamp_rep;
    } u;
} __attribute__((__packed__)); // pack the data structure

class Icmp_Layer {
    public:
        explicit Icmp_Layer() = default;
        ~Icmp_Layer() = default;

        int Serialize(uint8_t *buf, size_t buf_size, size_t &off, icmp_header *icmp_h);
        int Deserialize(uint8_t *buf, size_t buf_size, size_t &off, icmp_header *icmp_h);
        void Print(icmp_header *icmp_h);
};

}

#endif


