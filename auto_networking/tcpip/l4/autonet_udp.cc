#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <helpers.h>
#include <autonet_udp.h>

namespace auto_os::network {

int Udp_Packet::Serialize(uint8_t *buf, size_t buf_size, size_t &off, udp_header *udp_h)
{
    uint16_t val;

    val = auto_os::lib::bswap16b(udp_h->source_port);
    memcpy(buf + off, &val, sizeof(val));
    off += 2;

    val = auto_os::lib::bswap16b(udp_h->dest_port);
    memcpy(buf + off, &val, sizeof(val));
    off += 2;

    val = auto_os::lib::bswap16b(udp_h->length);
    memcpy(buf + off, &val, sizeof(val));
    off += 2;

    val = auto_os::lib::bswap16b(udp_h->checksum);
    memcpy(buf + off, &val, sizeof(val));
    off += 2;

    return off;
}

int Udp_Packet::Deserialize(uint8_t *buf, size_t buf_size, size_t &off, udp_header *udp_h)
{
    uint16_t val;

    memcpy(&val, buf + off, 2);
    udp_h->source_port = auto_os::lib::bswap16b(val);
    off += 2;

    memcpy(&val, buf + off, 2);
    udp_h->dest_port = auto_os::lib::bswap16b(val);
    off += 2;

    memcpy(&val, buf + off, 2);
    udp_h->length = auto_os::lib::bswap16b(val);
    off += 2;

    memcpy(&val, buf + off, 2);
    udp_h->checksum = auto_os::lib::bswap16b(val);
    off += 2;

    return off;
}

void Udp_Packet::Print(udp_header *udp_h)
{
    fprintf(stderr, "UDP: {\n");
    fprintf(stderr, "\t source port : %d\n", udp_h->source_port);
    fprintf(stderr, "\t destination port : %d\n", udp_h->dest_port);
    fprintf(stderr, "\t length : %d\n", udp_h->length);
    fprintf(stderr, "\t checksum : %d\n", udp_h->checksum);
    fprintf(stderr, "}\n");
}

}

