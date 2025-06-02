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
        auto& protection = session.get_tls_protection();

        auto key = session.get_tls_protection().get_keyexchange();

        constexpr char constexpr_master_secret[] = "93be6304758c8b4f0e106df7bbbb7a4edc23ed6188d44ed4d567b6e375400a74471fda4ad6748c84bda37a19399bd4a4";
        protection.use_pre_master_secret(true);
        protection.set_item(tls_secret_master, base16_decode(constexpr_master_secret));

        play_pcap(&session, pcap_dtls12, sizeof_pcap_dtls12);
    }

    {
        _test_case.begin("DTLS dtls12mtu1500.pcapng");
        tls_session session(session_type_dtls);
        auto& protection = session.get_tls_protection();

        auto key = session.get_tls_protection().get_keyexchange();
        keychain.load_file(&key, key_certfile, "server.crt", KID_TLS_SERVER_CERTIFICATE_PUBLIC);
        keychain.load_file(&key, key_pemfile, "server.key", KID_TLS_SERVER_CERTIFICATE_PRIVATE);

        constexpr char constexpr_master_secret[] = "cb07e6d5e5abef6d1c36bd39a5433b66f1932d485a40b0aa374c613f1630a91502daeda8f3a9c87007aa2d64c855be24";
        protection.use_pre_master_secret(true);
        protection.set_item(tls_secret_master, base16_decode(constexpr_master_secret));

        play_pcap(&session, pcap_dtls12_mtu1500, sizeof_pcap_dtls12_mtu1500);
    }
}
