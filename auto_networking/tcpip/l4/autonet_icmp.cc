#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <helpers.h>
#include <autonet_icmp.h>

namespace auto_os::network {

int Icmp_Layer::Serialize(uint8_t *buf, size_t buf_size, size_t &off, icmp_header *icmp_h)
{
    uint16_t checksum;

    buf[off] = icmp_h->type;
    off ++;

    buf[off] = icmp_h->code;
    off ++;

    checksum = auto_os::lib::bswap16b(icmp_h->checksum);
    memcpy(buf + off, &checksum, 2);
    off += 2;
}

int Icmp_Layer::Deserialize(uint8_t *buf, size_t buf_size, size_t &off, icmp_header *icmp_h)
{
    icmp_h->type = buf[off];
    off ++;

    icmp_h->code = buf[off];
    off ++;

    memcpy(&icmp_h->checksum, buf + off, 2);
    icmp_h->checksum = auto_os::lib::bswap16b(icmp_h->checksum);
    off += 2;

    // parse next data elements based on control
    switch (icmp_h->type) {
        case ICMP_TYPE_TIMESTAMP_REPLY:
            memcpy(&icmp_h->u.tstamp.identifier, buf + off, 2);
            off += 2;

            memcpy(&icmp_h->u.tstamp.seq_no, buf + off, 2);
            off += 2;

            memcpy(&icmp_h->u.tstamp.originate_timestamp, buf + off, 4);
            off += 4;

            memcpy(&icmp_h->u.tstamp.receive_timestamp, buf + off, 4);
            off += 4;

            memcpy(&icmp_h->u.tstamp.transmit_timestamp, buf + off, 4);
            off += 4;
        break;
        case ICMP_TYPE_TIMESTAMP:
            memcpy(&icmp_h->u.tstamp_rep.identifier, buf + off, 2);
            off += 2;

            memcpy(&icmp_h->u.tstamp_rep.seq_no, buf + off, 2);
            off += 2;

            memcpy(&icmp_h->u.tstamp_rep.originate_timestamp, buf + off, 4);
            off += 4;

            memcpy(&icmp_h->u.tstamp_rep.transmit_timestamp, buf + off, 4);
            off += 4;
        break;
        case ICMP_TYPE_ECHO_REPLY:
            memcpy(&icmp_h->u.echo_rep.identifier, buf + off, 2);
            //icmp_h->u.echo_rep.identifier = auto_os::lib::bswap16b(icmp_h->u.echo_rep.identifier);
            off += 2;

            memcpy(&icmp_h->u.echo_rep.seq_no, buf + off, 2);
            //icmp_h->u.echo_rep.seq_no = auto_os::lib::bswap16b(icmp_h->u.echo_rep.seq_no);
            off += 2;
        break;
        case ICMP_TYPE_ECHO_REQUEST:
            memcpy(&icmp_h->u.echo_req.identifier, buf + off, 2);
            //icmp_h->u.echo_req.identifier = auto_os::lib::bswap16b(icmp_h->u.echo_req.identifier);
            off += 2;

            memcpy(&icmp_h->u.echo_req.seq_no, buf + off, 2);
            //icmp_h->u.echo_req.seq_no = auto_os::lib::bswap16b(icmp_h->u.echo_req.seq_no);
            off += 2;
        break;
    }

    return off;
}

void Icmp_Layer::Print(icmp_header *icmp_h)
{
    fprintf(stderr, "icmp: {\n");
    fprintf(stderr, "\t type %d\n", icmp_h->type);
    fprintf(stderr, "\t code %d\n", icmp_h->code);
    fprintf(stderr, "\t checksum 0x%04x\n", icmp_h->checksum);
    switch (icmp_h->type) {
        case ICMP_TYPE_ECHO_REPLY:
            fprintf(stderr, "\t\t identifier 0x%04x\n", icmp_h->u.echo_rep.identifier);
            fprintf(stderr, "\t\t seq no 0x%04x\n", icmp_h->u.echo_rep.seq_no);
        break;
        case ICMP_TYPE_ECHO_REQUEST:
            fprintf(stderr, "\t\t identifier 0x%04x\n", icmp_h->u.echo_req.identifier);
            fprintf(stderr, "\t\t seq no 0x%04x\n", icmp_h->u.echo_req.seq_no);
        break;
    }
    fprintf(stderr, "}\n");
}

}

