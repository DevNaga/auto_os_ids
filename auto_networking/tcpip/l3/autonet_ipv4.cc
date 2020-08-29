/**
 * @brief - ipv4 serialize and deserialize
 * 
 * @copyright - All rights reserved 2020-present Devendra Naga (devendra.aaru@outlook.com)
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <autonet_ipv4.h>
#include <arpa/inet.h>
#include <helpers.h>

namespace auto_os::network {

Ipv4_Packet::Ipv4_Packet()
{
}

Ipv4_Packet::~Ipv4_Packet()
{
}

int Ipv4_Packet::Serialize(uint8_t *buf, size_t buf_size, size_t &off, ipv4_header *ipv4_h)
{
    uint16_t data;

    buf[off] = ipv4_h->version << 4;
    buf[off] |= (ipv4_h->ihl / 4);
    off ++;

    buf[off] = ipv4_h->dscp << 2;
    buf[off] |= ipv4_h->ecn;
    off ++;

    data = auto_os::lib::bswap16b(ipv4_h->total_len);
    memcpy(buf + off, &data, 2);
    off += 2;

    data = auto_os::lib::bswap16b(ipv4_h->identification);
    memcpy(buf + off, &data, 2);
    off += 2;

    if (ipv4_h->flags.reserved) {
        buf[off] |= 0x80;
    }
    if (ipv4_h->flags.dont_fragment) {
        buf[off] |= 0x40;
    }
    if (ipv4_h->flags.more_fragments) {
        buf[off] |= 0x20;
    }
    buf[off] |= (ipv4_h->frag_off & 0x1F00);
    off ++;

    buf[off] = (ipv4_h->frag_off & 0x00FF);
    off ++;

    buf[off] = ipv4_h->ttl;
    off ++;

    buf[off] = ipv4_h->protocol;
    off ++;

    data = auto_os::lib::bswap16b(ipv4_h->hdr_chksum);
    memcpy(buf + off, &data, 2);
    off += 2;

    data = auto_os::lib::bswap32b(ipv4_h->source_ipaddr);
    memcpy(buf + off, &data, 4);
    off += 4;

    data = auto_os::lib::bswap32b(ipv4_h->destination_ipaddr);
    memcpy(buf + off, &data, 4);
    off += 4;

    // TBD.. options
    return off;
}

int Ipv4_Packet::Deserialize(uint8_t *buf, size_t buf_size, size_t &off, ipv4_header *ipv4_h)
{
    // version always 4 .. 4 bits
    ipv4_h->version = (buf[off] & 0xF0) >> 4;

    // ihl = ihl * 4; .. 4 bits
    ipv4_h->ihl = (buf[off] & 0x0F) * 4;

    off ++;

    // dscp 6 bits
    ipv4_h->dscp = (buf[off] & 0xFC) >> 2;

    // ecn 2 bits
    ipv4_h->ecn = buf[off] & 0x03;

    off ++;

    // total length 16 bits
    memcpy(&ipv4_h->total_len, buf + off, 2);
    ipv4_h->total_len = auto_os::lib::bswap16b(ipv4_h->total_len);

    // 2 bytes
    off += 2;

    // identification .. 2 bytes
    memcpy(&ipv4_h->identification, buf + off, 2);
    ipv4_h->identification = auto_os::lib::bswap16b(ipv4_h->identification);

    off += 2;

    int flags;

    // flags .. 3 bits
    ipv4_h->flags.reserved = !!(buf[off] & 0x80);
    ipv4_h->flags.dont_fragment = !!(buf[off] & 0x40);
    ipv4_h->flags.more_fragments = !!(buf[off] & 0x20);

    // fragmentation offset .. 13 bits
    ipv4_h->frag_off = ((buf[off] & 0x1F) << 8) | (buf[off + 1]);

    off += 2;

    // 8 bits
    ipv4_h->ttl = buf[off];

    off ++;

    // 8 bits
    ipv4_h->protocol = buf[off];

    off ++;

    // hdr checksum 16 bits
    memcpy(&ipv4_h->hdr_chksum, buf + off, 2);
    ipv4_h->hdr_chksum = auto_os::lib::bswap16b(ipv4_h->hdr_chksum);

    off += 2;

    // source ipv4 address .. comes in big endian
    memcpy(&ipv4_h->source_ipaddr, buf + off, 4);
    off += 4;

    // dest ipv4 address .. comes in big endian
    memcpy(&ipv4_h->destination_ipaddr, buf + off, 4);
    off += 4;

    return off;
}

void Ipv4_Packet::Print(ipv4_header *ipv4)
{
    fprintf(stderr, "ipv4_header {\n");
    fprintf(stderr, "\t version: %d\n", ipv4->version);
    fprintf(stderr, "\t ihl: %d\n", ipv4->ihl);
    fprintf(stderr, "\t dscp: %d\n", ipv4->dscp);
    fprintf(stderr, "\t ecn: %d\n", ipv4->ecn);
    fprintf(stderr, "\t total len: %d\n", ipv4->total_len);
    fprintf(stderr, "\t identification: 0x%04x\n", ipv4->identification);
    fprintf(stderr, "\t flags: {\n");
    fprintf(stderr, "\t\t reserved: %d\n", ipv4->flags.reserved);
    fprintf(stderr, "\t\t dont fragment: %d\n", ipv4->flags.dont_fragment);
    fprintf(stderr, "\t\t more fragment: %d\n", ipv4->flags.more_fragments);
    fprintf(stderr, "\t}\n");
    fprintf(stderr, "\t frag_off: %d\n", ipv4->frag_off);
    fprintf(stderr, "\t ttl: %d\n", ipv4->ttl);
    fprintf(stderr, "\t protocol: 0x%x\n", ipv4->protocol);
    fprintf(stderr, "\t hdr_chksum: 0x%04x\n", ipv4->hdr_chksum);

    struct in_addr addr;

    addr.s_addr = ipv4->source_ipaddr;
    fprintf(stderr, "\t source ipaddr : %s\n", inet_ntoa(addr));

    addr.s_addr = ipv4->destination_ipaddr;
    fprintf(stderr, "\t dest ipaddr : %s\n", inet_ntoa(addr));
    fprintf(stderr, "}\n");
}

}


