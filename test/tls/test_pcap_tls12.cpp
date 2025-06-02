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
        tls_session session_etm(session_type_tls);
        auto& protection = session_etm.get_tls_protection();

        constexpr char constexpr_master_secret[] = "3a3847a4d20f9766ff81040b9db89f85f56b1b9526afc626c0138e5b89d62c74680af78ba4d827ee38989518845bc985";
        protection.use_pre_master_secret(true);
        protection.set_item(tls_secret_master, base16_decode(constexpr_master_secret));

        play_pcap(&session_etm, pcap_tls12etm_aes128cbc_sha256, sizeof_pcap_tls12etm_aes128cbc_sha256);
    }

    _test_case.begin("TLS 1.2 tls12mte_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256.pcapng");
    {
        tls_session session_mte(session_type_tls);
        auto& protection = session_mte.get_tls_protection();

        constexpr char constexpr_master_secret[] = "1598a9701b35936119d3b114b9b4df696d3d0fbcd92ee122612b59cdf0752f392e3ff27b38b9b585aa60e09408833a36";
        protection.use_pre_master_secret(true);
        protection.set_item(tls_secret_master, base16_decode(constexpr_master_secret));

        play_pcap(&session_mte, pcap_tls12mte_aes128cbc_sha256, sizeof_pcap_tls12mte_aes128cbc_sha256);
    }

    // GCM (EVP_CipherUpdate 1, EVP_CipherFinal 0 - decryption passed but authentication failed)
    _test_case.begin("TLS 1.2 tls12_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.pcapng");
    {
        tls_session session_gcm(session_type_tls);
        auto& protection = session_gcm.get_tls_protection();

        constexpr char constexpr_master_secret[] = "20c27d23fd3f64170b2b63917ccfe7251b792ea9492fa52b59c6adccc71095102e72ad1b08880a78f3f8316c1234a89b";
        protection.use_pre_master_secret(true);
        protection.set_item(tls_secret_master, base16_decode(constexpr_master_secret));

        play_pcap(&session_gcm, capture_tls12_aes128gcm_sha256, sizeof_capture_tls12_aes128gcm_sha256);
    }
}
