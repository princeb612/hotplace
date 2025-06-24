/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void test_http3() {
    _test_case.begin("HTTP/3");

    tls_session tlssession(session_type_tls);
    tls_session quicsession(session_type_quic);

    auto& quic_protection = quicsession.get_tls_protection();
    quic_protection.set_cipher_suite(0x1301);
    quic_protection.set_item(tls_context_quic_dcid, std::move(base16_decode("bd21df6a65e76e9e")));
    quic_protection.calc(&quicsession, tls_hs_client_hello, from_client);

    return_t ret = errorcode_t::success;
    for (auto i = 0; i < sizeof_pcap_http3; i++) {
        auto item = pcap_http3 + i;
        binary_t bin_frame = std::move(base16_decode_rfc(item->frame));
        if (SOCK_DGRAM == item->prot) {
            uint8 type = 0;
            quic_read_packet(type, &quicsession, item->dir, bin_frame);
        } else {
            //
        }
    }
}
