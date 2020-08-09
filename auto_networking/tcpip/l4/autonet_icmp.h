#ifndef __AUTONET_ICMP_H__
#define __AUTONET_ICMP_H__

#include <stdint.h>

namespace auto_os::net {

#define ICMP_TYPE_ECHO_REPLY                0
#define ICMP_TYPE_DESTINATION_UNREACHABLE   3
#define ICMP_TYPE_SOURCE_QUENCH             4
#define ICMP_TYPE_REDIRECT_MESSAGE          5
#define ICMP_TYPE_ECHO_REQUEST              8
#define ICMP_TYPE_ROUTER_ADVERTISEMENT      9
#define ICMP_TYPE_ROUTER_SOLICITATION       10
#define ICMP_TYPE_TIME_EXCEEDED             11
#define ICMP_TYPE_PARAMETER_PROBLEM         12
#define ICMP_TYPE_TIMESTAMP                 13
#define ICMP_TYPE_TIMESTAMP_REPLY           14
#define ICMP_TYPE_INFORMATION_REQUEST       15
#define ICMP_TYPE_INFORMATION_REPLY         16
#define ICMP_TYPE_ADDRESS_MASK_REQUEST      17
#define ICMP_TYPE_ADDRESS_MASK_REPLY        18
#define ICMP_TYPE_TRCEROUTE                 30
#define ICMP_TYPE_EXTENDED_ECHO_REQUEST     42
#define ICMP_TYPE_EXTENDED_ECHO_REPLY       43

struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;

#endif


