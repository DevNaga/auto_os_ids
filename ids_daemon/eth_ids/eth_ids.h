#ifndef __AUTO_MIDDLEWARE_ETH_IDS_H__
#define __AUTO_MIDDLEWARE_ETH_IDS_H__

#include <thread>
#include <mutex>
#include <condition_variable>
#include <socket_api.h>

namespace auto_os::middleware {

class eth_ids {
    public:
        explicit eth_ids();
        ~eth_ids();

        void start();
    private:
        void receive_thread();
        std::unique_ptr<auto_os::lib::raw_socket> r_;
        std::unique_ptr<std::thread> rx_thr_;
};

}

#endif


