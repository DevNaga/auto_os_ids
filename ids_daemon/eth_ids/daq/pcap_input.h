/**
 * @brief - implements pcap input for reply
 * 
 * @copyright - All rights reserved 2020-present Devendra Naga (devendra.aaru@outlook.com)
 */
#ifndef __AUTO_MIDDLEWARE_IDS_PCAP_INPUT_H__
#define __AUTO_MIDDLEWARE_IDS_PCAP_INPUT_H__

#include <memory>
#include <pcap_op.h>

namespace auto_os::middleware {

class pcap_input {
    public:
        explicit pcap_input(const std::string filename);
        pcap_input(pcap_input &) = delete;
        const pcap_input &operator=(pcap_input &) = delete;
        ~pcap_input();

        int read_record(auto_os::lib::pcap_rechdr_t *rec_hdr, uint8_t *record, size_t record_len);

    private:
        std::unique_ptr<auto_os::lib::pcap_op> op_;
};

}

#endif


