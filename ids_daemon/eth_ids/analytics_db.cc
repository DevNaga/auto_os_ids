#include <iostream>
#include <array>
#include <vector>
#include <analytics.h>

namespace auto_os::middleware {

void analytics_db::update_vlan_ids(uint16_t vlan, traffic_direction dir)
{
    l2_vlan_denials vland;

    vland.vlan_id = vlan;
    vland.traf = dir;

    vlan_deny_list.push_back(vland);
}

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

/**
 * @brief - create and write header to event log
 */
int analytics_db::create_event_log(const std::string &logfile)
{
    event_fp_ = fopen(logfile.c_str(), "w");
    if (!event_fp_) {
        return -1;
    }

    fprintf(event_fp_, "event_id, "
                       "event_timestamp_sec, "
                       "event_timestamp_nsec, "
                       "macaddr_src, "
                       "macaddr_dst, "
                       "ipv4_src, "
                       "ipv4_dst, "
                       "traffic_dir, "
                       "decision");
    fflush(event_fp_);

    return 0;
}

analytics_db::~analytics_db()
{
    if (event_fp_) {
        fflush(event_fp_);
        fclose(event_fp_);
    }
}

analytics_db::analytics_db() : event_fp_(nullptr)
{

}

}

