#ifndef __AUTO_OS_ETHERNET_H__
#define __AUTO_OS_ETHERNET_H__

#include <types.h>

namespace auto_os::net {

enum class Ether_Types {
    Ethertype_Arp,
    EtherType_Ipv4 = 0x0800,
};

struct Ethernet_Header {
    uint8_t *dest;
    uint8_t *src;
    uint16_t ethertype;
};

}

#endif

