#include <iostream>
#include <array>
#include <vector>
#include <analytics.h>

namespace auto_os::middleware {

void analytics_db::update_ethertype_denial(uint16_t ethertype, traffic_direction dir)
{
    l2_ethertype_denials ethtyped;

    ethtyped.ethertype = ethertype;
    ethtyped.traf = dir;

    l2_ethertype_deny_list.push_back(ethtyped);
}

void analytics_db::update_mac_denial(uint8_t *denied_mac, traffic_direction dir)
{
    l2_mac_denials l2d;

    l2d.denied_mac[0] = denied_mac[0];
    l2d.denied_mac[1] = denied_mac[1];
    l2d.denied_mac[2] = denied_mac[2];
    l2d.denied_mac[3] = denied_mac[3];
    l2d.denied_mac[4] = denied_mac[4];
    l2d.denied_mac[5] = denied_mac[5];
    l2d.traf = dir;

    l2_mac_deny_list.push_back(l2d);
}

}


