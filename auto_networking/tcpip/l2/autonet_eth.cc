#include <autonet_eth.h>
#include <string.h>
#include <helpers.h>
#include <autonet_ethertypes.h>

namespace auto_os::network {


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

}


