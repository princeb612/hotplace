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

void test_pcap_tls12() {
    return_t ret = errorcode_t::success;

    _test_case.begin("TLS 1.2 tls12etm_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256.pcapng");
    {
        tls_session session(session_type_tls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "CLIENT_RANDOM 968988b10ed8d72be87faea564a0d815a462f141ca8019adc533aec989152bff "
                        "3a3847a4d20f9766ff81040b9db89f85f56b1b9526afc626c0138e5b89d62c74680af78ba4d827ee38989518845bc985";

        play_pcap(&session, pcap_tls12etm_aes128cbc_sha256, sizeof_pcap_tls12etm_aes128cbc_sha256);
    }

    _test_case.begin("TLS 1.2 tls12mte_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256.pcapng");
    {
        tls_session session(session_type_tls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "CLIENT_RANDOM 8806aaf3bab7cfa006497ef50620ddae5320bf1541d2d2a97afb85145aa1d275 "
                        "1598a9701b35936119d3b114b9b4df696d3d0fbcd92ee122612b59cdf0752f392e3ff27b38b9b585aa60e09408833a36";

        play_pcap(&session, pcap_tls12mte_aes128cbc_sha256, sizeof_pcap_tls12mte_aes128cbc_sha256);
    }

    _test_case.begin("TLS 1.2 tls12_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.pcapng");
    {
        tls_session session(session_type_tls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "CLIENT_RANDOM 8d4e72acf55111544eadc50e5e9e0c3015648025881194328bce1573dec89ed6 "
                        "20c27d23fd3f64170b2b63917ccfe7251b792ea9492fa52b59c6adccc71095102e72ad1b08880a78f3f8316c1234a89b";

        play_pcap(&session, pcap_tls12_aes128gcm_sha256, sizeof_pcap_tls12_aes128gcm_sha256);
    }

    _test_case.begin("tls12_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.pcapng");
    {
        tls_session session(session_type_tls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "CLIENT_RANDOM 19587698676b7fe86d78564051c0c44d0d8123939567dafbc01bbf8f78b323c0 "
                        "6525943d87978a14a4553a956b6f71501d0cbfd97aa856ce69b9aca4a7b5c1209d663b389778393170e9e4c068e51843";

        play_pcap(&session, pcap_tls12_chacha20poly1305_sha256, sizeof_pcap_tls12_chacha20poly1305_sha256);
    }
}
