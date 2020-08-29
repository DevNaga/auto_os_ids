/**
 * @brief - ARP serialize and deserialize
 * 
 * @copyright - All rights reserved 2020-present Devendra Naga (devendra.aaru@outlook.com)
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <autonet_arp.h>
#include <helpers.h>

namespace auto_os::network {

int Arp_Layer::Serialize(uint8_t *buf, size_t buf_size, size_t &off, arp_header *arp_h)
{
    uint16_t data;

    data = auto_os::lib::bswap16b(static_cast<int>(arp_h->hw_type));
    memcpy(buf + off, &data, sizeof(data));
    off += 2;

    data = auto_os::lib::bswap16b(arp_h->proto_type);
    memcpy(buf + off, &data, sizeof(data));
    off += 2;

    buf[off] = arp_h->hw_addr_len;
    off ++;

    buf[off] = arp_h->protocol_addr_len;
    off ++;

    data = auto_os::lib::bswap16b(static_cast<int>(arp_h->op));
    memcpy(buf + off, &data, sizeof(data));
    off += 2;

    memcpy(buf + off, arp_h->sender_hwaddr, 6);
    off += 6;

    memcpy(buf + off, arp_h->sender_proto_addr, 4);
    off += 4;

    memcpy(buf + off, arp_h->target_hwaddr, 6);
    off += 6;

    memcpy(buf + off, arp_h->target_proto_addr, 4);
    off += 4;

    return -1;
}

int Arp_Layer::Deserialize(uint8_t *buf, size_t buf_size, size_t &off, arp_header *arp_h)
{
    uint16_t data;

    memcpy(&data, buf + off, 2);
    off += 2;

    arp_h->hw_type = static_cast<hardware_type>(data);

    memcpy(&arp_h->proto_type, buf + off, 2);
    off += 2;

    arp_h->hw_addr_len = buf[off];
    off ++;

    arp_h->protocol_addr_len = buf[off];
    off ++;

    memcpy(&data, buf + off, 2);
    off += 2;

    arp_h->op = static_cast<operation>(data);

    memcpy(arp_h->sender_hwaddr, buf + off, 6);
    off += 6;

    memcpy(arp_h->sender_proto_addr, buf + off, 4);
    off += 4;

    memcpy(arp_h->target_hwaddr, buf + off, 6);
    off += 6;

    memcpy(arp_h->target_proto_addr, buf + off, 4);
    off += 4;

    return off;
}

void Arp_Layer::Pretty_Print(arp_header *arp_h)
{
    fprintf(stderr, "Arp: {\n");
    fprintf(stderr, "\t hw_type : %d\n", static_cast<int>(arp_h->hw_type));
    fprintf(stderr, "\t protocol type : %d\n", arp_h->proto_type);
    fprintf(stderr, "\t hw addr len : %d\n", arp_h->hw_addr_len);
    fprintf(stderr, "\t protocol addr len : %d\n", arp_h->protocol_addr_len);
    fprintf(stderr, "\t operation : %d\n", static_cast<int>(arp_h->op));
    fprintf(stderr, "\t sender hw addr : [%02x:%02x:%02x:%02x:%02x:%02x]\n",
                            arp_h->sender_hwaddr[0],
                            arp_h->sender_hwaddr[1],
                            arp_h->sender_hwaddr[2],
                            arp_h->sender_hwaddr[3],
                            arp_h->sender_hwaddr[4],
                            arp_h->sender_hwaddr[5]);
    fprintf(stderr, "\t sender proto addr : [%02d.%02d.%02d.%02d]\n",
                            arp_h->sender_proto_addr[0],
                            arp_h->sender_proto_addr[1],
                            arp_h->sender_proto_addr[2],
                            arp_h->sender_proto_addr[3]);
    fprintf(stderr, "\t target hw addr : [%02x:%02x:%02x:%02x:%02x:%02x]\n",
                            arp_h->target_hwaddr[0],
                            arp_h->target_hwaddr[1],
                            arp_h->target_hwaddr[2],
                            arp_h->target_hwaddr[3],
                            arp_h->target_hwaddr[4],
                            arp_h->target_hwaddr[5]);
    fprintf(stderr, "\t target proto addr : [%02d.%02d.%02d.%02d]\n",
                            arp_h->target_proto_addr[0],
                            arp_h->target_proto_addr[1],
                            arp_h->target_proto_addr[2],
                            arp_h->target_proto_addr[3]);
    fprintf(stderr, "}\n");
}

}

