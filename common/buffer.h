#ifndef __AUTO_OS_BUFFER_H__
#define __AUTO_OS_BUFFER_H__

#include <ethernet.h>

namespace auto_os::network {

struct buffer {
    uint16_t eth_off;
    struct Ethernet_Header *eth;
};

}

#endif

