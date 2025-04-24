/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <random>

#include "sample.hpp"

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

udp_traffic _traffic;

static return_t do_test_construct_client_hello(tls_direction_t dir, tls_session* session, const char* message) {
    return_t ret = errorcode_t::success;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    tls_handshake_client_hello* handshake = nullptr;

    __try2 {
        __try_new_catch(handshake, new tls_handshake_client_hello(session), ret, __leave2);

        // random
        {
            openssl_prng prng;

            binary_t random;  // gmt_unix_time(4 bytes) + random(28 bytes)
            time_t gmt_unix_time = time(nullptr);
            binary_append(random, gmt_unix_time, hton64);
            random.resize(sizeof(uint32));
            binary_t temp;
            prng.random(temp, 28);
            binary_append(random, temp);
            handshake->set_random(random);
        }

        // cipher suites
        {
            *handshake << "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
                       << "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"
                       << "TLS_ECDHE_ECDSA_WITH_AES_128_CCM:TLS_ECDHE_ECDSA_WITH_AES_256_CCM"
                       << "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"
                       << "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
                       << "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
                       << "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
        }

        {
            auto ec_point_formats = new tls_extension_ec_point_formats(session);
            (*ec_point_formats).add("uncompressed");
            handshake->get_extensions().add(ec_point_formats);
        }
        {
            auto supported_groups = new tls_extension_supported_groups(session);
            (*supported_groups)
                .add("x25519")
                .add("secp256r1")
                .add("x448")
                .add("secp521r1")
                .add("secp384r1")
                .add("ffdhe2048")
                .add("ffdhe3072")
                .add("ffdhe4096")
                .add("ffdhe6144")
                .add("ffdhe8192");
            handshake->get_extensions().add(supported_groups);
        }
        {
            auto signature_algorithms = new tls_extension_signature_algorithms(session);
            (*signature_algorithms)
                .add("ecdsa_secp256r1_sha256")
                .add("ecdsa_secp384r1_sha384")
                .add("ecdsa_secp521r1_sha512")
                .add("ed25519")
                .add("ed448")
                .add("rsa_pkcs1_sha256")
                .add("rsa_pkcs1_sha384")
                .add("rsa_pkcs1_sha512")
                .add("rsa_pss_pss_sha256")
                .add("rsa_pss_pss_sha384")
                .add("rsa_pss_pss_sha512")
                .add("rsa_pss_rsae_sha256")
                .add("rsa_pss_rsae_sha384")
                .add("rsa_pss_rsae_sha512");
            handshake->get_extensions().add(signature_algorithms);
        }
        {
            auto supported_versions = new tls_extension_client_supported_versions(session);
            (*supported_versions).add(dtls_12);
            handshake->get_extensions().add(supported_versions);
        }
    }
    __finally2 {
        if (errorcode_t::success == ret) {
#if 0
            {
                // cross-check : record in single block
                binary_t tbin;
                tls_session tsession(session_dtls);
                tls_record_handshake trecord(&tsession);
                trecord.get_handshakes().add(handshake, true);
                trecord.write(dir, tbin);
            }
#endif

            tls_record_handshake record(session);
            record << handshake;
            // do not call record.write (not to affect epoch, sequence, ...)

            // sketch
            std::vector<tls_record*> records;
            session->get_dtls_record_publisher().publish(records, record, dir);
            for (auto fragment : records) {
                binary_t bin_fragmented_record;
                fragment->write(dir, bin_fragmented_record);
                _traffic.sendto(std::move(bin_fragmented_record));
                fragment->release();
            }
        }

        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_send_record(tls_direction_t dir, tls_session* session, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == message) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto& reorder = session->get_dtls_record_reorder();

        // sketch - reorder, reassemble

        // UDP traffic
        _traffic.shuffle();
        auto lambda = [&](const binary_t& bin) { reorder.produce(&bin[0], bin.size()); };
        _traffic.consume(lambda);

        // reorder
        binary_t bin;
        uint16 epoch = 0;
        uint64 seq = 0;

        while (1) {
            auto test = reorder.consume(epoch, seq, bin);
            if (empty == test) {
                break;
            } else if (not_ready == test) {
                continue;
            }

            _logger->hdump(format("epoch %i seq %I64i", epoch, seq).c_str(), bin, 16, 3);

            // tls_records records;
            // records.read(session, dir, bin);
        }
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 1, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

void test_construct_dtls12() {
    _test_case.begin("construct DTLS 1.2");

    tls_session session_client(session_dtls);
    tls_session session_server(session_dtls);

    session_client.get_dtls_record_publisher().set_fragment_size(128);

    do_test_construct_client_hello(from_client, &session_client, "client hello");
    do_test_send_record(from_client, &session_server, "client hello");
}
