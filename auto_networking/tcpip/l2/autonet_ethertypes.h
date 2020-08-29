/**
 * @brief - ethertypes
 * 
 * @copyright - All rights reserved 2020-present Devendra Naga (devendra.aaru@outlook.com)
 */
#ifndef __AUTONET_ETHERTYPES_H__
#define __AUTONET_ETHERTYPES_H__

namespace auto_os::network {

enum class ethertypes : int {
    IPV4                                    = 0x0800,
    ARP                                     = 0x0806,
    WAKE_ON_LAN                             = 0x0842,
    AVTP                                    = 0x22F0,
    IETF_TRILL_PROTOCOL                     = 0x22F3,
    STREAM_RESERVATION_PROTOCOL             = 0x22EA,
    DEC_MOP_RC                              = 0x6002,
    DECNET_PHASE_4_DNA_ROUTING              = 0x6003,
    DEC_LAT                                 = 0x6004,
    RARP                                    = 0x8035,
    APPLETALK                               = 0x809B,
    APPLETALK_ARP                           = 0x80F3,
    IEEE8021Q_VLAN                          = 0x8100,
    SLPP                                    = 0x8102,
    VLCAP                                   = 0x8103,
    IPX                                     = 0x8137,
    QNX_QNET                                = 0x8204,
    IPV6                                    = 0x86DD,
    ETHERNET_FLOW_CONTROL                   = 0x8808,
    LACP                                    = 0x8809,
    COBRANET                                = 0x8819,
    MPLS_UNICAST                            = 0x8847,
    MPLS_MULTICAST                          = 0x8848,
    PPPOE_DISCOVERY_STAGE                   = 0x8863,
    PPPOE_SESSION_STAGE                     = 0x8864,
    HOPEPLUG_1_0_MME                        = 0x887B,
    EAP_OVER_LAN                            = 0x888E,
    PROFINET                                = 0x8892,
    HYPER_SCSI                              = 0x889A,
    ATA_OVER_ETHERNET                       = 0x88A2,
    ETHERCAT                                = 0x88A4,
    SERVICE_VLAN_TAG_ID_ON_Q_IN_Q_TUNNEL    = 0x88A8,
    ETHERNET_POWERLINK                      = 0x88AB,
    GOOSE                                   = 0x88B8,
    GSE                                     = 0x88B9,
    SV                                      = 0x88BA,
    MIKROTIK_ROMON                          = 0x88BF,
    LLDP                                    = 0x88CC,
    SERCOS_III                              = 0x88CD,
    WSMP                                    = 0x88DC,
    MEDIA_REDUNDANCY_PROTOCOL               = 0x88E3,
    MAC_SECURITY                            = 0x88E5,
    PROVIDER_BACKBONE_BRIDGES               = 0x88E7,
    PTP_OVER_802_3                          = 0x88F7,
    NC_SI                                   = 0x88F8,
    PRP                                     = 0x88FB,
    IEEE_8021AG_CFM                         = 0x8902,
    FCOE                                    = 0x8906,
    FCOE_INITIALIZATION_PROTOCOL            = 0x8914,
    ROCE                                    = 0x8915,
    TTE                                     = 0x891D,
    HSR                                     = 0x892F,
    ETHERNET_CONFIG_TESTING                 = 0x9000,
    IEEE_8021Q_VLAN_TAG_DOUBLE_TAGGING      = 0x9100,
    REDUNDANCY_TAG                          = 0xF1C1
};

}

#endif


