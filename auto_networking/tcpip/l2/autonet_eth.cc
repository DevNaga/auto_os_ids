/**
 * @brief - implements ethernet interface serializer and deserializer
 * 
 * @copyright - All rights reserved 2020-present Devendra Naga (devendra.aaru@outlook.com)
 */
#include <autonet_eth.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <helpers.h>
#include <autonet_ethertypes.h>

namespace auto_os::network {

static const uint8_t ethernet_ptp_mac[] = {0x01, 0x1B, 0x19, 0x00, 0x00, 0x00};
static const uint8_t ethernet_ptp_mac_2[] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};

Ethernet_Layer::Ethernet_Layer()
{
}

Ethernet_Layer::~Ethernet_Layer()
{
}

int Ethernet_Layer::Serialize(uint8_t *buf, size_t buf_size, size_t &off, ethernet_header *eth)
{
    uint16_t ethertype = auto_os::lib::bswap16b(eth->ethertype);
    memcpy(buf + off, eth->dest, 6);
    off += 6;

    memcpy(buf + off, eth->src, 6);
    off += 6;

    memcpy(buf + off, &ethertype, 2);
    off += 2;

    return off;
}

int Ethernet_Layer::Deserialize(uint8_t *buf, size_t buf_size, size_t &off, ethernet_header *eth)
{
    uint16_t ethertype;

    memcpy(eth->dest, buf + off, 6);
    off += 6;

    memcpy(eth->src, buf + off, 6);
    off += 6;

    memcpy(&ethertype, buf + off, 2);
    off += 2;

    eth->ethertype = auto_os::lib::bswap16b(ethertype);

    return off;
}

int Ieee8021q_Vlan::Serialize(uint8_t *buf, size_t buf_size, size_t &off, ieee_8021q_vlan *vlan)
{
    buf[off] = (vlan->pcp << 5);
    buf[off] |= (!!(vlan->dei)) << 4;
    buf[off] |= (vlan->vlan_id & 0x0F00) >> 8;
    off ++;

    buf[off] |= (vlan->vlan_id & 0x00FF);
    off ++;

    return off;
}

int Ieee8021q_Vlan::Deserialize(uint8_t *buf, size_t buf_size, size_t &off, ieee_8021q_vlan *vlan)
{
    vlan->tpid = ethertypes::IEEE8021Q_VLAN;

    vlan->pcp = (buf[off] & 0xE0) >> 5;
    vlan->dei = !!(buf[off] & 0x10);
    vlan->vlan_id = ((buf[off] & 0x0F) << 8) | (buf[off + 1]);
    off += 2;

    return off;
}

void Ieee8021q_Vlan::Pretty_Print(ieee_8021q_vlan *vlan)
{
    fprintf(stderr, "VLAN : {\n");
    fprintf(stderr, "\t pcp : %d\n", vlan->pcp);
    fprintf(stderr, "\t dei : %d\n", vlan->dei);
    fprintf(stderr, "\t vlan id : %d\n", vlan->vlan_id);
    fprintf(stderr, "}\n");
}

Ieee8021q_Vlan::Ieee8021q_Vlan()
{

}

Ieee8021q_Vlan::~Ieee8021q_Vlan()
{

}

}

