#ifndef __AUTO_MIDDLEWARE_ETH_IDS_H__
#define __AUTO_MIDDLEWARE_ETH_IDS_H__

#include <thread>
#include <mutex>
#include <condition_variable>
#include <socket_api.h>
#include <monitor_engine.h>
#include <pcap_input.h>

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
};

class eth_ids {
    public:
        explicit eth_ids();
        ~eth_ids();

        void start();
    private:
        void receive_thread();
        void replay_thread();
        std::unique_ptr<auto_os::lib::raw_socket> r_;
        std::unique_ptr<std::thread> rx_thr_;
        std::unique_ptr<std::thread> replay_thr_;
        std::unique_ptr<monitor_engine> e_;
        std::unique_ptr<pcap_input> pcap_in_;
        eth_ids_config ids_data_;
};

}

#endif


