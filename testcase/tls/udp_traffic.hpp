/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   udp_traffic.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_TLS13_UDPTRAFFIC__
#define __HOTPLACE_TEST_TLS13_UDPTRAFFIC__

#include <random>
#include "sample.hpp"

// simulate traffic
class udp_traffic {
   public:
    udp_traffic() {}

    void sendto(binary_t&& bin) {
        critical_section_guard guard(_lock);
        if (rand() % 4 == 0) _packets.push_back(bin);  // duplication test
        _packets.push_back(std::move(bin));
    }
    return_t recvfrom(binary_t& bin) {
        return_t ret = errorcode_t::success;
        critical_section_guard guard(_lock);
        if (_packets.empty()) {
            ret = errorcode_t::empty;
        } else {
            auto iter = _packets.begin();
            bin = std::move(*iter);
            _packets.erase(iter);
        }
        return ret;
    }
    void shuffle(uint32 seed = 0) {
        critical_section_guard guard(_lock);
        if (0 == seed) {
            if (rand() % 2 == 0) {
                // https://en.cppreference.com/w/cpp/algorithm/random_shuffle
                std::random_device rd;
                std::mt19937 g(rd());
                std::shuffle(_packets.begin(), _packets.end(), g);

            } else {
                std::reverse(_packets.begin(), _packets.end());
            }
        } else {
            // deterministic replay
            std::mt19937 rng(seed);
            std::shuffle(_packets.begin(), _packets.end(), rng);
        }
    }
    void consume(std::function<void(binary_t&&)> fn) {
        std::vector<binary_t> packets;

        {
            critical_section_guard guard(_lock);
            packets.swap(_packets);
        }

        for (auto& packet : packets) {
            fn(std::move(packet));
        }
    }

   private:
    critical_section _lock;
    std::vector<binary_t> _packets;
};

#endif
