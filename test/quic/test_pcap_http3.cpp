/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void test_pcap_http3() {
    _test_case.begin("HTTP/3");

    tls_session tlssession(session_type_tls);
    tls_session quicsession(session_type_quic);

    auto sslkeylog = sslkeylog_importer::get_instance();
    sslkeylog->attach(&tlssession);
    sslkeylog->attach(&quicsession);

    // QUIC client_random 48124abae04c7ad67bd69bb976916edf349a0b296c884ba22f546faed8c8ce90
    // TLS client_random 95bed2d24d72386f90f77864e5fdfa4ba00357955d70957456e3743e00fe6b8c
    // no TLS SSLKEYLOG
    *sslkeylog << "SERVER_HANDSHAKE_TRAFFIC_SECRET 48124abae04c7ad67bd69bb976916edf349a0b296c884ba22f546faed8c8ce90 "
                  "617086660ff9b9b9ef915feec02c039b651732233d0b71dc8b6b18eb75c983f09f7ddb3a39c1490e41c1356112a984ef";
    *sslkeylog << "CLIENT_HANDSHAKE_TRAFFIC_SECRET 48124abae04c7ad67bd69bb976916edf349a0b296c884ba22f546faed8c8ce90 "
                  "e315f79a78300f88b0864fcd0e41ab998554ae79bfd200748f9bf97f31e1fbb998b733112ad64221d4932fc722630236";
    *sslkeylog << "EXPORTER_SECRET 48124abae04c7ad67bd69bb976916edf349a0b296c884ba22f546faed8c8ce90 "
                  "a7c32716b38ca7379bdf3e3ca62c06ce4a086bcb5dc7e8d71973b5b6d520e2e657d3ecc1fb9fc34713e8a9cdc2c2ac29";
    *sslkeylog << "SERVER_TRAFFIC_SECRET_0 48124abae04c7ad67bd69bb976916edf349a0b296c884ba22f546faed8c8ce90 "
                  "55929ee9456ec7f86032f4154886aef7b29507a7e36bc044c03f7a0c27310b8a246b4ddb2406ca94fc2caf9dff6b5254";
    *sslkeylog << "CLIENT_TRAFFIC_SECRET_0 48124abae04c7ad67bd69bb976916edf349a0b296c884ba22f546faed8c8ce90 "
                  "3bcc36729cb515e3e85d1685a5eb9a8ac3b977f02c7e0d481773c76a19bd97adfbfce4f6359a6e6b8741a506713a23ae";

    return_t ret = errorcode_t::success;
    for (auto i = 0; i < sizeof_pcap_http3; i++) {
        auto item = pcap_http3 + i;
        auto prot = item->prot;
        auto dir = item->dir;
        binary_t bin_frame = std::move(base16_decode_rfc(item->frame));

        _logger->colorln(item->desc);

        if (item->debug) {
            int breakpoint_here = 1;
        }
        if (prot_quic == prot) {
            // WIRESHARK#14 contains 2 PACKETs
            quic_packets packets;
            ret = packets.read(&quicsession, dir, bin_frame);
        } else if (prot_tls13 == prot) {
            // tls_records records;
            // ret = records.read(&tlssession, dir, bin_frame);
            ret = do_nothing;
        }

        _test_case.test(ret, __FUNCTION__, "%s", item->desc);
    }
}
