#include <iostream>
#include <pcap_input.h>

namespace auto_os::middleware {

pcap_input::pcap_input(const std::string filename)
{
    op_ = std::make_unique<auto_os::lib::pcap_op>(filename, auto_os::lib::pcap_op_type::read_op);
}

pcap_input::~pcap_input()
{
}

int pcap_input::read_record(auto_os::lib::pcap_rechdr_t *rec_hdr, uint8_t *record, size_t record_len)
{
    int ret;

    ret = op_->read_record(*rec_hdr, record, record_len);
    if (ret < 0) {
        return -1;
    }

    return ret;
}

}


