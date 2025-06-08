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

#include "sample.hpp"

void test_pcap_dtls12() {
    // dtlsserver
    // openssl s_client -connect localhost:9000 -state -debug -dtls1_2

    return_t ret = errorcode_t::success;

    crypto_keychain keychain;
    tls_advisor* advisor = tls_advisor::get_instance();

    {
        _test_case.begin("DTLS dtls12.pcapng");
        tls_session session(session_type_dtls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "CLIENT_RANDOM 9fc7e253870b87faa821b77616c4c36f606f82ed8cd786d70af2d4236e992e07 "
                        "93be6304758c8b4f0e106df7bbbb7a4edc23ed6188d44ed4d567b6e375400a74471fda4ad6748c84bda37a19399bd4a4";

        play_pcap(&session, pcap_dtls12, sizeof_pcap_dtls12);
    }

    {
        _test_case.begin("DTLS dtls12mtu1500.pcapng");
        tls_session session(session_type_dtls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "CLIENT_RANDOM 72d43426a55aa0095ff3ac7c6990fec0008dad754d097cf70458cb9e49b28927 "
                        "cb07e6d5e5abef6d1c36bd39a5433b66f1932d485a40b0aa374c613f1630a91502daeda8f3a9c87007aa2d64c855be24";

        play_pcap(&session, pcap_dtls12_mtu1500, sizeof_pcap_dtls12_mtu1500);
    }

    {
        _test_case.begin("DTLS dtls12_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.pcapng");
        tls_session session(session_type_dtls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "CLIENT_RANDOM e6e48c6fe8940ca4e964275444130933bb9c2df627d0ee61e65490bfb01b4f54 "
                        "e4fee12a44ea9b47af65f83485aa5d44d4796e6cdd66781b6b00da1f774f054489c76471a0ae2e7e236f2f5e2a71c448";

        play_pcap(&session, pcap_dtls12_aes128gcm, sizeof_pcap_dtls12_aes128gcm);
    }
}
