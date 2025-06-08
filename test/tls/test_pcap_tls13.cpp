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

        tls_session session(session_type_tls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "SERVER_HANDSHAKE_TRAFFIC_SECRET 809e8158ce5615096911896042afa66b1bdf63678c35ace06618e5da520c2ded "
                        "173f64c03a1f2be84418c226be95396d493a262d9c0c31e06cf6fcbf77083e00";
        (*sslkeylog) << "CLIENT_HANDSHAKE_TRAFFIC_SECRET 809e8158ce5615096911896042afa66b1bdf63678c35ace06618e5da520c2ded "
                        "747fb5763d962534c3bae4bf2af31a3e83fac020241842c6eb5e8d925d38e0e0";
        (*sslkeylog) << "EXPORTER_SECRET 809e8158ce5615096911896042afa66b1bdf63678c35ace06618e5da520c2ded "
                        "72103e6785dbad8f2a62af7f78aaddffaab6b5e8bb4a2eb1d8f701b8a8196862";
        (*sslkeylog) << "SERVER_TRAFFIC_SECRET_0 809e8158ce5615096911896042afa66b1bdf63678c35ace06618e5da520c2ded "
                        "0fc45c37bf9ee0675e337b7fa53b052a8f1444d1e1626ec0e3207ef186334415";
        (*sslkeylog) << "CLIENT_TRAFFIC_SECRET_0 809e8158ce5615096911896042afa66b1bdf63678c35ace06618e5da520c2ded "
                        "78e236e89ebc5759d212eb5f5a548185cba9f511643d8e58afa2e0665f34806b";

        play_pcap(&session, pcap_tls13_aes128gcm_sha256, sizeof_pcap_tls13_aes128gcm_sha256);
    }

    {
        _test_case.begin("TLS 1.3 tls13_TLS_AES_256_GCM_SHA384.pcapng");

        tls_session session(session_type_tls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "SERVER_HANDSHAKE_TRAFFIC_SECRET b9398c3af35d1401fe4aa62ea94b264337f185bc844e1bc2dded3586b8dae225 "
                        "e232d8af6204b54f5e85d8c93cb3b2f69fc13ff439e029b6d9ec95a0175451bf333c312ebfa032fa44624a688bf954b8";
        (*sslkeylog) << "EXPORTER_SECRET b9398c3af35d1401fe4aa62ea94b264337f185bc844e1bc2dded3586b8dae225 "
                        "02e5c7ebbe3315502d186dfb8385092e303472483e861aeb2c89accefead3e249b55150bb195bd82c7f1e05b017ca6fa";
        (*sslkeylog) << "SERVER_TRAFFIC_SECRET_0 b9398c3af35d1401fe4aa62ea94b264337f185bc844e1bc2dded3586b8dae225 "
                        "cc899e0330367316bb2ab23949dc71a991b38b42025dc1fa9a05643b161c9ec1f0c6696f60b5ed8ef76524779b0e5abb";
        (*sslkeylog) << "CLIENT_HANDSHAKE_TRAFFIC_SECRET b9398c3af35d1401fe4aa62ea94b264337f185bc844e1bc2dded3586b8dae225 "
                        "1a469cb11a59d969868f7e62a939233422ad82ee6d866eebb5dc17cd2f32b2916be8706c9e63fe24294763e36ae1ea38";
        (*sslkeylog) << "CLIENT_TRAFFIC_SECRET_0 b9398c3af35d1401fe4aa62ea94b264337f185bc844e1bc2dded3586b8dae225 "
                        "7c6e80aea2d0f6f9411f921fcd28963383a82d54d01cd8f2a822ee8dce354fb7984b7211785e36de6ec19fcb9bcd1cb8";

        play_pcap(&session, pcap_tls13_aes256gcm_sha384, sizeof_pcap_tls13_aes256gcm_sha384);
    }

    {
        _test_case.begin("TLS 1.3 tls13_TLS_AES_128_CCM_SHA256.pcapng");

        tls_session session(session_type_tls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "SERVER_HANDSHAKE_TRAFFIC_SECRET 20e466267b480ed91949cb1c275038026be816b9b4bbd490cc1ce5645eb5c6b7 "
                        "d1e102620ceaf58facc136927bbf631591a4d2204cecf17352aacc0561a05e02";
        (*sslkeylog) << "CLIENT_HANDSHAKE_TRAFFIC_SECRET 20e466267b480ed91949cb1c275038026be816b9b4bbd490cc1ce5645eb5c6b7 "
                        "a65f00bc1f1f76927fe6b21c286b164781a63190555b54cbb9c45e8f4001e8d2";
        (*sslkeylog) << "EXPORTER_SECRET 20e466267b480ed91949cb1c275038026be816b9b4bbd490cc1ce5645eb5c6b7 "
                        "26e19951270472527de1aebf58db1f537892d96287d4e8458d8f145b6f20168d";
        (*sslkeylog) << "SERVER_TRAFFIC_SECRET_0 20e466267b480ed91949cb1c275038026be816b9b4bbd490cc1ce5645eb5c6b7 "
                        "f4da140ae8c6fbed7a59ea863b3a459e5e15fc9ddd5a2baa8021dfe1de635713";
        (*sslkeylog) << "CLIENT_TRAFFIC_SECRET_0 20e466267b480ed91949cb1c275038026be816b9b4bbd490cc1ce5645eb5c6b7 "
                        "ec139d3054dbb41adcbf6b185ad737668d29ab4a517ce5eddc7083336dbbd857";

        play_pcap(&session, pcap_tls13_aes128ccm_sha256, sizeof_pcap_tls13_aes128ccm_sha256);
    }

    {
        _test_case.begin("TLS 1.3 tls13_TLS_CHACHA20_POLY1305_SHA256.pcapng");

        tls_session session(session_type_tls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "SERVER_HANDSHAKE_TRAFFIC_SECRET c55d7de4cca2ee3f725ca027cbb30a1bf3b857f2962aa4b7bccf3106bbc9e7b3 "
                        "601dd4dcc3277dbb3969a464b716f1fe868d2af6424d1f04481a472103bc899b";
        (*sslkeylog) << "CLIENT_HANDSHAKE_TRAFFIC_SECRET c55d7de4cca2ee3f725ca027cbb30a1bf3b857f2962aa4b7bccf3106bbc9e7b3 "
                        "965272c3a3c1a8df580ec6edb4eeb5b779ea32ea2b702a65016356816d5f1a81";
        (*sslkeylog) << "EXPORTER_SECRET c55d7de4cca2ee3f725ca027cbb30a1bf3b857f2962aa4b7bccf3106bbc9e7b3 "
                        "f6488a46c930058d717a710036b10de556560eac12805a6c39238e980c02a40b";
        (*sslkeylog) << "SERVER_TRAFFIC_SECRET_0 c55d7de4cca2ee3f725ca027cbb30a1bf3b857f2962aa4b7bccf3106bbc9e7b3 "
                        "bad5f6924fa2ab3a258e1c8c4168fddd09c05fb8cd29573ef24850d1b4ad73a4";
        (*sslkeylog) << "CLIENT_TRAFFIC_SECRET_0 c55d7de4cca2ee3f725ca027cbb30a1bf3b857f2962aa4b7bccf3106bbc9e7b3 "
                        "788b2e29a6ce9dff91b21231e775a59e345aaf79bbdc5e9d371afeb6548142b9";

        play_pcap(&session, pcap_tls13_chacha20_poly1305, sizeof_pcap_tls13_chacha20_poly1305);
    }
}
