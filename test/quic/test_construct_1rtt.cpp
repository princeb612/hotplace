/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void test_construct_1rtt() {
    _test_case.begin("construct 1-RTT");

    // http3.pcapng WIRESHARK#62 ACK

    tls_session quicsession(session_type_quic);                      // QUIC 1
    quicsession.get_tls_protection().set_cipher_suite(0x1302);       // TLS_AES_256_GCM_SHA384
    auto& secrets = quicsession.get_tls_protection().get_secrets();  // QUIC client header protection, key, initial vector
    secrets.assign(tls_secret_application_quic_client_hp, base16_decode("3fdbae30616d0a07cdf5d80ca1bcbc8c70a73ca4aa6344312afe100d28bb5ba5"));
    secrets.assign(tls_secret_application_quic_client_key, base16_decode("30e8e78feec5efc175e62f42f3fa7888d41123fa87d104c3493311a8047a6c56"));
    secrets.assign(tls_secret_application_quic_client_iv, base16_decode("097284612fb7e8bbee84fa20"));
    secrets.assign(tls_context_server_cid, base16_decode("fe21df6a65e76e9e"));  // DCID

    return_t ret = errorcode_t::success;
    auto dir = from_client;

    // read (PKN 14)
    {
        constexpr char ciphertext[] =
            "42 fe 21 df 6a 65 e7 6e 9e 86 10 55 47 10 c5 1f"
            "3d b6 29 03 24 ad 7d 9c 9d 00 8e 87 fe 08 57 3f"
            "7b 5d 0d 3f";

        binary_t bin_ciphertext = std::move(base16_decode_rfc(ciphertext));
        quic_packets packets;
        ret = packets.read(&quicsession, dir, bin_ciphertext);
        auto pkt = packets[0];
        _test_case.assert(14 == pkt->get_pn(), __FUNCTION__, "PKN");
        _test_case.test(ret, __FUNCTION__, "read");
    }

    // write & read (PKN 15)
    {
        auto recno = quicsession.get_recordno(dir, false, protection_application);

        /**
         *  > frame ACK 0x2(2) @0x0
         *   > largest ack 24
         *   > ack delay 0
         *   > ack range count 1
         *   > first ack range 10
         *   > ack ranges[0]
         *    > gap 0
         *    > range length 5
         */
        constexpr char payload[] = "02 18 00 01 0A 00 05";
        binary_t bin_payload = std::move(base16_decode_rfc(payload));
        binary_t bin_packet;

        quic_packet_1rtt packet(&quicsession);
        packet.set_pn(recno, 4);
        packet.set_dcid(secrets.get(tls_context_server_cid));
        packet.set_payload(bin_payload);
        ret = packet.write(dir, bin_packet);

        _logger->hdump("packet", bin_packet);
        _test_case.test(ret, __FUNCTION__, "write");

        // check
        quic_packets packets;
        ret = packets.read(&quicsession, dir, bin_packet);
        auto pkt = packets[0];
        _test_case.assert(15 == pkt->get_pn(), __FUNCTION__, "PKN");
        _test_case.test(ret, __FUNCTION__, "read");
    }
}
