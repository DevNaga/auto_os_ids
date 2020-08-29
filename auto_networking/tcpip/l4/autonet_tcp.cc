/**
 * @brief - implements tcp serialize and deserialize
 * 
 * @copyright - All rights reserved 2020-present Devendra Naga (devendra.aaru@outlook.com)
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <helpers.h>
#include <autonet_tcp.h>

namespace auto_os::network {

int Tcp_Layer::Deserialize(uint8_t *buf, size_t buf_size, size_t &off, tcp_header *tcp_h)
{
    uint16_t data16;

    memcpy(&data16, buf + off, 2);
    off += 2;

    tcp_h->source_port = auto_os::lib::bswap16b(data16);

    memcpy(&data16, buf + off, 2);
    off += 2;

    tcp_h->dest_port = auto_os::lib::bswap16b(data16);

    memcpy(&tcp_h->seq_no, buf + off, 4);
    off += 4;

    memcpy(&tcp_h->ack_no, buf + off, 4);
    off += 4;

    tcp_h->data_offset = buf[off] & 0xF0 >> 4;
    tcp_h->reserved = buf[off] & 0x0E >> 1;
    tcp_h->ns = !!(buf[off] & 0x01);
    off ++;

    tcp_h->cwr = !!(buf[off] & 0x80);
    tcp_h->ece = !!(buf[off] & 0x40);
    tcp_h->urg = !!(buf[off] & 0x20);
    tcp_h->ack = !!(buf[off] & 0x10);
    tcp_h->psh = !!(buf[off] & 0x08);
    tcp_h->rst = !!(buf[off] & 0x04);
    tcp_h->syn = !!(buf[off] & 0x02);
    tcp_h->fin = !!(buf[off] & 0x01);

    off ++;

    memcpy(&data16, buf + off, 2);
    off += 2;

    tcp_h->window_size = auto_os::lib::bswap16b(data16);

    memcpy(&data16, buf + off, 2);
    off += 2;

    tcp_h->checksum = auto_os::lib::bswap16b(data16);

    memcpy(&data16, buf + off, 2);
    off += 2;

    tcp_h->urg_pointer = auto_os::lib::bswap16b(data16);
    off += 2;

    // TBD: parsing of option fields
    return off;
}

int Tcp_Layer::Serialize(uint8_t *buf, size_t buf_size, size_t &off, tcp_header *tcp_h)
{
    uint16_t data16;

    data16 = auto_os::lib::bswap16b(tcp_h->source_port);
    memcpy(buf + off, &data16, 2);
    off += 2;

    data16 = auto_os::lib::bswap16b(tcp_h->dest_port);
    memcpy(buf + off, &data16, 2);
    off += 2;

    memcpy(buf + off, &tcp_h->seq_no, 4);
    off += 4;

    memcpy(buf + off, &tcp_h->ack_no, 4);
    off += 4;

    buf[off] |= (tcp_h->data_offset << 4);
    buf[off] |= (tcp_h->reserved << 1);
    buf[off] |= (tcp_h->ns);
    off ++;

    buf[off] |= (tcp_h->cwr << 7);
    buf[off] |= (tcp_h->ece << 6);
    buf[off] |= (tcp_h->urg << 5);
    buf[off] |= (tcp_h->ack << 4);
    buf[off] |= (tcp_h->psh << 3);
    buf[off] |= (tcp_h->rst << 2);
    buf[off] |= (tcp_h->syn << 1);
    buf[off] |= (tcp_h->fin);
    off ++;

    data16 = auto_os::lib::bswap16b(tcp_h->window_size);
    memcpy(buf + off, &data16, 2);
    off += 2;

    data16 = auto_os::lib::bswap16b(tcp_h->checksum);
    memcpy(buf + off, &data16, 2);
    off += 2;

    data16 = auto_os::lib::bswap16b(tcp_h->urg_pointer);
    memcpy(buf + off, &data16, 2);
    off += 2;

    return off;
}

void Tcp_Layer::Print(tcp_header *tcp_h)
{
    fprintf(stderr, "tcp: {\n");
    fprintf(stderr, "\t source port : %d\n", tcp_h->source_port);
    fprintf(stderr, "\t dest port : %d\n", tcp_h->dest_port);
    fprintf(stderr, "\t seq no : %u\n", tcp_h->seq_no);
    fprintf(stderr, "\t ack no : %u\n", tcp_h->ack_no);
    fprintf(stderr, "\t data offset : %d\n", tcp_h->data_offset);
    fprintf(stderr, "\t reserved : %d\n", tcp_h->reserved);
    fprintf(stderr, "\t ns : %d\n", tcp_h->ns);
    fprintf(stderr, "\t cwr : %d\n", tcp_h->cwr);
    fprintf(stderr, "\t ece : %d\n", tcp_h->ece);
    fprintf(stderr, "\t urg : %d\n", tcp_h->urg);
    fprintf(stderr, "\t ack : %d\n", tcp_h->ack);
    fprintf(stderr, "\t psh : %d\n", tcp_h->psh);
    fprintf(stderr, "\t rst : %d\n", tcp_h->rst);
    fprintf(stderr, "\t syn : %d\n", tcp_h->syn);
    fprintf(stderr, "\t fin : %d\n", tcp_h->fin);
    fprintf(stderr, "\t window size : 0x%04x\n", tcp_h->window_size);
    fprintf(stderr, "\t checksum : 0x%04x\n", tcp_h->checksum);
    fprintf(stderr, "\t urg_pointer : 0x%04x\n", tcp_h->urg_pointer);
    fprintf(stderr, "}\n");
}

}

