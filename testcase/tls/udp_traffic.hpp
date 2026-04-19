#ifndef __HOTPLACE_TEST_TLS13_UDPTRAFFIC__
#define __HOTPLACE_TEST_TLS13_UDPTRAFFIC__

// simulate traffic
class udp_traffic {
   public:
    udp_traffic() {}

    void sendto(binary_t&& bin) {
        critical_section_guard guard(_lock);
        _packets.push_back(std::move(bin));
    }
    return_t recvfrom(binary_t& bin) {
        return_t ret = errorcode_t::success;
        if (_packets.empty()) {
            ret = errorcode_t::empty;
        } else {
            critical_section_guard guard(_lock);
            auto iter = _packets.begin();
            bin = std::move(*iter);
            _packets.erase(iter);
        }
        return ret;
    }
    void shuffle() {
        critical_section_guard guard(_lock);
        // https://en.cppreference.com/w/cpp/algorithm/random_shuffle
        std::random_device rd;
        std::mt19937 g(rd());
        std::shuffle(_packets.begin(), _packets.end(), g);
    }
    void consume(std::function<void(const binary_t&)> fn) {
        critical_section_guard guard(_lock);
        for (auto packet : _packets) {
            fn(packet);
        }
        _packets.clear();
    }

   private:
    critical_section _lock;
    std::vector<binary_t> _packets;
};

#endif
