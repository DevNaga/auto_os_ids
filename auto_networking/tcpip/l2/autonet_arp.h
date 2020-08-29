/**
 * @brief - arp serialize and deserialize
 * 
 * @copyright - All rights reserved 2020-present Devendra Naga (devendra.aaru@outlook.com)
 */
#ifndef __AUTO_NETWORK_ARP_H__
#define __AUTO_NETWORK_ARP_H__

#include <stdint.h>

namespace auto_os::network {

enum class hardware_type : int {
    eEthernet,
    eIeee802,
    eArcnet,
    eFrameRelay,
    eAtm,
    eHdlc,
    eFiberChannel,
    eAtm2,
    eSerialLine,
};

enum class operation : int {
    eArpRequest,
    eArpReply,
    eRarpRequest,
    eRarpReply,
    eDrarpRequest,
    eDrarpReply,
    eDrarpError,
    eInarpRequest,
    eInarpReply,
};

struct arp_header {
    hardware_type       hw_type;
    uint16_t            proto_type;
    uint8_t             hw_addr_len;
    uint8_t             protocol_addr_len;
    operation           op;
    uint8_t             sender_hwaddr[6]; // mac address
    uint8_t             sender_proto_addr[4]; // ipv4 address
    uint8_t             target_hwaddr[6]; // mac address
    uint8_t             target_proto_addr[4]; // ipv4 address
};

class Arp_Layer {
    public:
        explicit Arp_Layer() = default;
        ~Arp_Layer() = default;

        int Serialize(uint8_t *buf, size_t buf_size, size_t &off, arp_header *arp_h);
        int Deserialize(uint8_t *buf, size_t buf_size, size_t &off, arp_header *arp_h);
        void Pretty_Print(arp_header *arp_h);
};

}

#endif


