#include <iostream>
#include <thread>
#include <mutex>
#include <memory>
#include <condition_variable>
#include <string>
#include <eth_ids.h>
#include <socket_api.h>

#define ETH_IDS_DEV_NAME "enp0s3"

namespace auto_os::middleware {

eth_ids::eth_ids()
{
    r_ = std::make_unique<auto_os::lib::raw_socket>(ETH_IDS_DEV_NAME, 0);
    rx_thr_ = std::make_unique<std::thread>(&eth_ids::receive_thread, this);
}

eth_ids::~eth_ids()
{
}

void eth_ids::receive_thread()
{
    int sock = r_->get_socket();
    int ret;

    while (1) {
    }
}

void eth_ids::start()
{
    rx_thr_->join();
}

}

int main()
{
    auto_os::middleware::eth_ids eth_ids;

    eth_ids.start();
}

