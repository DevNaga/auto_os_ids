#ifndef __AUTO_NETWORK_IPV4_H__
#define __AUTO_NETWORK_IPV4_H__

#include <types.h>
#include <autonet_ip_protocols.h>

namespace auto_os::network {

struct ipv4_flags {
    bool reserved;
    bool dont_fragment;
    bool more_fragments;
};

struct ipv4_header {
    int version; // always 4
    int ihl;
    // to be used by the library only!
    int dscp;

    // to be used by the library only!
    int ecn;
    short int total_len;
    short int identification;
    ipv4_flags flags;

    // to be used by the library only!
    int frag_off;

    // to be used by the library only!
    unsigned char ttl;
    unsigned char protocol;
    short unsigned int hdr_chksum;
    unsigned int source_ipaddr;
    unsigned int destination_ipaddr;
    // options..
};

class Ipv4_Packet {
    public:
        explicit Ipv4_Packet();
        ~Ipv4_Packet();

        int Serialize(uint8_t *buf, size_t buf_size, size_t &off, ipv4_header *ipv4_h);
        int Deserialize(uint8_t *buf, size_t buf_size, size_t &off, ipv4_header *ipv4_h);
        void Print(ipv4_header *ipv4_h);
};

}

#endif


