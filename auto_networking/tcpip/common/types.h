#ifndef __AUTO_NETWORK_TYPES_H__
#define __AUTO_NETWORK_TYPES_H__

#include <string.h>
#include <helpers.h>

namespace auto_os::network {

const uint8_t macaddr_len = 6;
const uint8_t ipv4_addr_len = 4;
const uint8_t ipv6_addr_len_max = 16;

const uint8_t broadcast_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t zero_mac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t mcast_mac[] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x00};

enum class mac_type {
    ebroadcast,
    ezeromac,
    eunicast,
    emcast,
    eunknown,
};

/**
 * @brief - get the mac address type
 *
 * @param in mac - in mac
 * @param out mac_type - type of mac
 */
inline mac_type get_mac_type(uint8_t *mac)
{
    if (memcmp(mac, broadcast_mac, 6) == 0) {
        return mac_type::ebroadcast;
    }
    if (memcmp(mac, zero_mac, 6) == 0) {
        return mac_type::ezeromac;
    }
    if (memcmp(mac, mcast_mac, 6) == 0) {
        return mac_type::emcast;
    }

    return mac_type::eunknown;
}



const int IEEE_802_3_len_min = 0x0000;
const int IEEE_802_3_len_max = 0x05dc;

enum class ethertypes {
    ETHERTYPE_IP                    = 0x0800,
    ETHERTYPE_X75                   = 0x0801,
    ETHERTYPE_ARP                   = 0x0806,
    ETHERTYPE_RARP                  = 0x8035,
    ETHERTYPE_SNMP                  = 0x814C,
    ETHERTYPE_IPV6                  = 0x86DD,
    ETHERTYPE_PPP                   = 0x880B,
    ETHERTYPE_GSMP                  = 0x880C,
    ETHERTYPE_MPLS                  = 0x8847,
    ETHERTYPE_MPLS_LABLE            = 0x8848,
    ETHERTYPE_PPPOE_DISCOVERY       = 0x8863,
    ETHERTYPE_PPPOE_SESSION         = 0x8864,

    // 802.1Q VLAN Service VLAN tag identifier
    ETHERTYPE_8021Q_VLAN_TAG_S      = 0x88A8,

    // 802.11i preauth
    ETHERTYPE_80211_PREAUTH         = 0x88C7,

    ETHERTYPE_PTP                   = 0x88F7,

};

}

#endif


