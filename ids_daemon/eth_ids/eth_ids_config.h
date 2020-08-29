#ifndef __AUTO_MIDDLEWARE_ETH_IDS_CONFIG_H__
#define __AUTO_MIDDLEWARE_ETH_IDS_CONFIG_H__

namespace auto_os::middleware {

enum class daq_source {
    eInterface,
    ePcap,
};

struct eth_ids_config {
    daq_source daq;
    bool use_all_interfaces;
    std::string use_interface;
    std::string pcap_path;

    static eth_ids_config *instance() {
        static eth_ids_config ins;

        return &ins;
    }

    int parse();
    ~eth_ids_config() = default;
    private:
        eth_ids_config() = default;
};

}

#endif

