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

void test_pcap_tls13() {
    {
        _test_case.begin("TLS 1.3 tls13_TLS_AES_128_GCM_SHA256.pcapng");

        tls_session session_sclient(session_type_tls);
        auto& protection = session_sclient.get_tls_protection();

        protection.use_pre_master_secret(true);
        // SERVER_HANDSHAKE_TRAFFIC_SECRET (server_handshake_traffic_secret)
        protection.set_item(server_handshake_traffic_secret, base16_decode_rfc("173f64c03a1f2be84418c226be95396d493a262d9c0c31e06cf6fcbf77083e00"));
        // CLIENT_HANDSHAKE_TRAFFIC_SECRET (client_handshake_traffic_secret)
        protection.set_item(client_handshake_traffic_secret, base16_decode_rfc("747fb5763d962534c3bae4bf2af31a3e83fac020241842c6eb5e8d925d38e0e0"));
        // EXPORTER_SECRET
        protection.set_item(tls_secret_exp_master, base16_decode_rfc("72103e6785dbad8f2a62af7f78aaddffaab6b5e8bb4a2eb1d8f701b8a8196862"));
        // SERVER_TRAFFIC_SECRET_0 (server_application_traffic_secret_0)
        protection.set_item(server_application_traffic_secret_0, base16_decode_rfc("0fc45c37bf9ee0675e337b7fa53b052a8f1444d1e1626ec0e3207ef186334415"));
        // CLIENT_TRAFFIC_SECRET_0 (client_application_traffic_secret_0)
        protection.set_item(client_application_traffic_secret_0, base16_decode_rfc("78e236e89ebc5759d212eb5f5a548185cba9f511643d8e58afa2e0665f34806b"));

        play_pcap(&session_sclient, pcap_tls13_aes128gcm_sha256, sizeof_pcap_tls13_aes128gcm_sha256);
    }

    {
        _test_case.begin("TLS 1.3 tls13_TLS_AES_256_GCM_SHA384.pcapng");

        tls_session session_sclient(session_type_tls);
        auto& protection = session_sclient.get_tls_protection();

        protection.use_pre_master_secret(true);
        // SERVER_HANDSHAKE_TRAFFIC_SECRET (server_handshake_traffic_secret)
        protection.set_item(server_handshake_traffic_secret,
                            base16_decode_rfc("e232d8af6204b54f5e85d8c93cb3b2f69fc13ff439e029b6d9ec95a0175451bf333c312ebfa032fa44624a688bf954b8"));
        // CLIENT_HANDSHAKE_TRAFFIC_SECRET (client_handshake_traffic_secret)
        protection.set_item(client_handshake_traffic_secret,
                            base16_decode_rfc("1a469cb11a59d969868f7e62a939233422ad82ee6d866eebb5dc17cd2f32b2916be8706c9e63fe24294763e36ae1ea38"));
        // EXPORTER_SECRET
        protection.set_item(tls_secret_exp_master,
                            base16_decode_rfc("02e5c7ebbe3315502d186dfb8385092e303472483e861aeb2c89accefead3e249b55150bb195bd82c7f1e05b017ca6fa"));
        // SERVER_TRAFFIC_SECRET_0 (server_application_traffic_secret_0)
        protection.set_item(server_application_traffic_secret_0,
                            base16_decode_rfc("cc899e0330367316bb2ab23949dc71a991b38b42025dc1fa9a05643b161c9ec1f0c6696f60b5ed8ef76524779b0e5abb"));
        // CLIENT_TRAFFIC_SECRET_0 (client_application_traffic_secret_0)
        protection.set_item(client_application_traffic_secret_0,
                            base16_decode_rfc("7c6e80aea2d0f6f9411f921fcd28963383a82d54d01cd8f2a822ee8dce354fb7984b7211785e36de6ec19fcb9bcd1cb8"));

        play_pcap(&session_sclient, pcap_tls13_aes256gcm_sha384, sizeof_pcap_tls13_aes256gcm_sha384);
    }

    {
        _test_case.begin("TLS 1.3 tls13_TLS_AES_128_CCM_SHA256.pcapng");

        tls_session session_sclient(session_type_tls);
        auto& protection = session_sclient.get_tls_protection();

        protection.use_pre_master_secret(true);
        // SERVER_HANDSHAKE_TRAFFIC_SECRET (server_handshake_traffic_secret)
        protection.set_item(server_handshake_traffic_secret, base16_decode_rfc("d1e102620ceaf58facc136927bbf631591a4d2204cecf17352aacc0561a05e02"));
        // CLIENT_HANDSHAKE_TRAFFIC_SECRET (client_handshake_traffic_secret)
        protection.set_item(client_handshake_traffic_secret, base16_decode_rfc("a65f00bc1f1f76927fe6b21c286b164781a63190555b54cbb9c45e8f4001e8d2"));
        // EXPORTER_SECRET
        protection.set_item(tls_secret_exp_master, base16_decode_rfc("26e19951270472527de1aebf58db1f537892d96287d4e8458d8f145b6f20168d"));
        // SERVER_TRAFFIC_SECRET_0 (server_application_traffic_secret_0)
        protection.set_item(server_application_traffic_secret_0, base16_decode_rfc("f4da140ae8c6fbed7a59ea863b3a459e5e15fc9ddd5a2baa8021dfe1de635713"));
        // CLIENT_TRAFFIC_SECRET_0 (client_application_traffic_secret_0)
        protection.set_item(client_application_traffic_secret_0, base16_decode_rfc("ec139d3054dbb41adcbf6b185ad737668d29ab4a517ce5eddc7083336dbbd857"));

        play_pcap(&session_sclient, pcap_tls13_aes128ccm_sha256, sizeof_pcap_tls13_aes128ccm_sha256);
    }

    {
        _test_case.begin("TLS 1.3 tls13_TLS_CHACHA20_POLY1305_SHA256.pcapng");

        tls_session session_sclient(session_type_tls);
        auto& protection = session_sclient.get_tls_protection();

        protection.use_pre_master_secret(true);
        // SERVER_HANDSHAKE_TRAFFIC_SECRET (server_handshake_traffic_secret)
        protection.set_item(server_handshake_traffic_secret, base16_decode_rfc("601dd4dcc3277dbb3969a464b716f1fe868d2af6424d1f04481a472103bc899b"));
        // CLIENT_HANDSHAKE_TRAFFIC_SECRET (client_handshake_traffic_secret)
        protection.set_item(client_handshake_traffic_secret, base16_decode_rfc("965272c3a3c1a8df580ec6edb4eeb5b779ea32ea2b702a65016356816d5f1a81"));
        // EXPORTER_SECRET
        protection.set_item(tls_secret_exp_master, base16_decode_rfc("f6488a46c930058d717a710036b10de556560eac12805a6c39238e980c02a40b"));
        // SERVER_TRAFFIC_SECRET_0 (server_application_traffic_secret_0)
        protection.set_item(server_application_traffic_secret_0, base16_decode_rfc("bad5f6924fa2ab3a258e1c8c4168fddd09c05fb8cd29573ef24850d1b4ad73a4"));
        // CLIENT_TRAFFIC_SECRET_0 (client_application_traffic_secret_0)
        protection.set_item(client_application_traffic_secret_0, base16_decode_rfc("788b2e29a6ce9dff91b21231e775a59e345aaf79bbdc5e9d371afeb6548142b9"));

        play_pcap(&session_sclient, pcap_tls13_chacha20_poly1305, sizeof_pcap_tls13_chacha20_poly1305);
    }
}
