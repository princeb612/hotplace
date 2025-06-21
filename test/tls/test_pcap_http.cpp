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

void test_pcap_tls13_http1() {
    {
        _test_case.begin("TLS 1.3 http1.pcapng");

        tls_session session(session_type_tls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "SERVER_HANDSHAKE_TRAFFIC_SECRET c126cfafae8cb4f1ec61468e6f8b16db41bcb2bd16ff0c81610f8c40c5d028e4 "
                        "03baaf4ead28ab678c4c6643185eb1fe2699de129cd39e341579d82a7b7218b6";
        (*sslkeylog) << "CLIENT_HANDSHAKE_TRAFFIC_SECRET c126cfafae8cb4f1ec61468e6f8b16db41bcb2bd16ff0c81610f8c40c5d028e4 "
                        "8096092572254ce5bc0d0f1609ff6e0b9f0de2a2789c0e327504db5b3d8c09e2";
        (*sslkeylog) << "EXPORTER_SECRET c126cfafae8cb4f1ec61468e6f8b16db41bcb2bd16ff0c81610f8c40c5d028e4 "
                        "3d371adf33f888bd3b88f1249c6009621881c29368107f2741b40a8b9d9c7767";
        (*sslkeylog) << "SERVER_TRAFFIC_SECRET_0 c126cfafae8cb4f1ec61468e6f8b16db41bcb2bd16ff0c81610f8c40c5d028e4 "
                        "014469a0a1e8ca364a554a7dde68ab18d7a4c611d0bc5adc71952dc78fb7018d";
        (*sslkeylog) << "SERVER_HANDSHAKE_TRAFFIC_SECRET f9cef6ee59e41f07f495a835982451150e5ad090ff6b33547b56a364f58e8b62 "
                        "cb49c716f80e75180c4e0337b88d305c15fd59459945124fa95fae1cc73522c0";
        (*sslkeylog) << "CLIENT_HANDSHAKE_TRAFFIC_SECRET f9cef6ee59e41f07f495a835982451150e5ad090ff6b33547b56a364f58e8b62 "
                        "3f376c10a23552fc894187c1dbe853a72ac737f68ae4778f353d4daaa37963ad";
        (*sslkeylog) << "EXPORTER_SECRET f9cef6ee59e41f07f495a835982451150e5ad090ff6b33547b56a364f58e8b62 "
                        "d55fc9a65345c41ea52f76071340638216287b336a188e1c1c00d3012c371013";
        (*sslkeylog) << "SERVER_TRAFFIC_SECRET_0 f9cef6ee59e41f07f495a835982451150e5ad090ff6b33547b56a364f58e8b62 "
                        "1c6a88896c6103e4c5d2f64a98809ffb6671ec792e2953873644f65ef6945882";
        (*sslkeylog) << "CLIENT_TRAFFIC_SECRET_0 f9cef6ee59e41f07f495a835982451150e5ad090ff6b33547b56a364f58e8b62 "
                        "cd158cbf6313b8bffff5bc2236ae2caeba6f39b57f02c9aefdc076a67f23e7d6";

        play_pcap(&session, pcap_tls13_http1_aes128gcm_sha256, sizeof_pcap_tls13_http1_aes128gcm_sha256);
    }

    {
        _test_case.begin("TLS 1.3 http2.pcapng");

        tls_session session(session_type_tls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "SERVER_HANDSHAKE_TRAFFIC_SECRET e3d93634084c3563a9158c0dd798b45bce974ded17ecb84c60646f0551118ff5 "
                        "c61c37cb99ac81524791ab2bb185c0f1a7ff1a4c48e93d5875028d50d4f0b940";
        (*sslkeylog) << "CLIENT_HANDSHAKE_TRAFFIC_SECRET e3d93634084c3563a9158c0dd798b45bce974ded17ecb84c60646f0551118ff5 "
                        "84ddc65354be31fcbae31b3d2ffd03a640c198ddeaa70c0d0abba33515bec736";
        (*sslkeylog) << "EXPORTER_SECRET e3d93634084c3563a9158c0dd798b45bce974ded17ecb84c60646f0551118ff5 "
                        "9ed0fe4f15b289d31198e46e92c31dff838f5fecbc2e6b7de1a2688197dd653c";
        (*sslkeylog) << "SERVER_TRAFFIC_SECRET_0 e3d93634084c3563a9158c0dd798b45bce974ded17ecb84c60646f0551118ff5 "
                        "217fe8a3bbb07530fb65b8efd540397e5f195d10db541833801771f1767632e8";
        (*sslkeylog) << "SERVER_HANDSHAKE_TRAFFIC_SECRET 5f8ae41b1513965c566f57af03f20586571246376178a18126df3842905bb18b "
                        "fe0ccb864cf6c93db53450a2782f966834ee9951796efeee62f439e7cd9f1324";
        (*sslkeylog) << "CLIENT_HANDSHAKE_TRAFFIC_SECRET 5f8ae41b1513965c566f57af03f20586571246376178a18126df3842905bb18b "
                        "cdf711a6e6f3accce917638e9f523337d2df0355495c1eff67066756ef0d2101";
        (*sslkeylog) << "EXPORTER_SECRET 5f8ae41b1513965c566f57af03f20586571246376178a18126df3842905bb18b "
                        "33a97477d16ef72bc5a55bde8b02403e185ace5d897311d5125719e775f36d65";
        (*sslkeylog) << "SERVER_TRAFFIC_SECRET_0 5f8ae41b1513965c566f57af03f20586571246376178a18126df3842905bb18b "
                        "01cdeedeea6ca5a42eb50fcfab2c7fdaaed8159e54dc4eef15018d17cb1a266e";
        (*sslkeylog) << "SERVER_HANDSHAKE_TRAFFIC_SECRET 060252a6b68f1421a10d978a20c1d495ac2a65782643e688725b50263b8bfcfa "
                        "aca37f9b4b6cc4b556b2d4f41e77ec5ac8c3f8d6b848eb98ec05728a3fd66e37";
        (*sslkeylog) << "CLIENT_HANDSHAKE_TRAFFIC_SECRET 060252a6b68f1421a10d978a20c1d495ac2a65782643e688725b50263b8bfcfa "
                        "8a62a9043a953ef1385c46800908a23861e254c2ffd6b4baf35f5c124349c4ef";
        (*sslkeylog) << "EXPORTER_SECRET 060252a6b68f1421a10d978a20c1d495ac2a65782643e688725b50263b8bfcfa "
                        "0912558fc48d2117b7248d359adc55dfcdeb76524a92d483803b0d87c2af0a9d";
        (*sslkeylog) << "SERVER_TRAFFIC_SECRET_0 060252a6b68f1421a10d978a20c1d495ac2a65782643e688725b50263b8bfcfa "
                        "4c847438048e173fdf162ccc1ca903897e1818ab66d5e6ccbfa7a5eaec3d877a";
        (*sslkeylog) << "CLIENT_TRAFFIC_SECRET_0 060252a6b68f1421a10d978a20c1d495ac2a65782643e688725b50263b8bfcfa "
                        "653a4da8c8272ca0c9e044c8500ce096feea945f4c9dd306d24336230d007b7e";
        (*sslkeylog) << "SERVER_HANDSHAKE_TRAFFIC_SECRET f3d7566bf62c987da13f62746c7abd59790c39ec48022438bc0c98b0d5b20688 "
                        "363ead2736ed8bc30086824016dce913e733593c348e75fed0d8330b369254f7";
        (*sslkeylog) << "CLIENT_HANDSHAKE_TRAFFIC_SECRET f3d7566bf62c987da13f62746c7abd59790c39ec48022438bc0c98b0d5b20688 "
                        "4b1a3d5e96ce90f954d644d9ea78e09288063d1be8646544c6f00851f7be98e7";
        (*sslkeylog) << "EXPORTER_SECRET f3d7566bf62c987da13f62746c7abd59790c39ec48022438bc0c98b0d5b20688 "
                        "bd10f880f8b81bca919c1aa526be9d33f143ff5fb7d33c06de27d0892e3c087c";
        (*sslkeylog) << "SERVER_TRAFFIC_SECRET_0 f3d7566bf62c987da13f62746c7abd59790c39ec48022438bc0c98b0d5b20688 "
                        "2e7c95c2f567b682e613c608b9fa05acc8681c8ba404a5f5e8ee12360840a326";
        (*sslkeylog) << "CLIENT_TRAFFIC_SECRET_0 f3d7566bf62c987da13f62746c7abd59790c39ec48022438bc0c98b0d5b20688 "
                        "8d4ec3dfc408b1eeaf3d856f994535f3d6a7f5804902dec22c3c17005c76e104";
        (*sslkeylog) << "SERVER_HANDSHAKE_TRAFFIC_SECRET da445878bd727912794a3957ea64112bd20b74e92fef5177850b85055b9969dc "
                        "94b2e4c5bb4c620c7c4c52ff7e190ddab01dbf9369961a02c17b354dfb06df59";
        (*sslkeylog) << "CLIENT_HANDSHAKE_TRAFFIC_SECRET da445878bd727912794a3957ea64112bd20b74e92fef5177850b85055b9969dc "
                        "75cfcc02e6ff1b71442b864181bd6322e0e2eb674057e755f2341a48556f7573";
        (*sslkeylog) << "EXPORTER_SECRET da445878bd727912794a3957ea64112bd20b74e92fef5177850b85055b9969dc "
                        "0ca745bb522897181dcb7e3d99db4b36d9ad8e8b8b0a1b1648a60e435587096b";
        (*sslkeylog) << "SERVER_TRAFFIC_SECRET_0 da445878bd727912794a3957ea64112bd20b74e92fef5177850b85055b9969dc "
                        "f2c453d9025120aa0e490fb2e8586acea5f8534f5d623d03d5d2ff7363eae129";
        (*sslkeylog) << "SERVER_HANDSHAKE_TRAFFIC_SECRET 44b612097beeece79198b35a9599ea408fea42ec6200c5a5a531206af7caddc1 "
                        "58bf064530b619b43d7cdaf28b04b8ef9f721772f3d85f8cf2097c192e5d8712";
        (*sslkeylog) << "CLIENT_HANDSHAKE_TRAFFIC_SECRET 44b612097beeece79198b35a9599ea408fea42ec6200c5a5a531206af7caddc1 "
                        "5cef063663e932a411cfd753ca9bc0731fa51b85010fd9ee243f068480a00c16";
        (*sslkeylog) << "EXPORTER_SECRET 44b612097beeece79198b35a9599ea408fea42ec6200c5a5a531206af7caddc1 "
                        "57b7f379af6b6abe7eddf7c5870887050a9628f190d956654626c1325faa36e9";
        (*sslkeylog) << "SERVER_TRAFFIC_SECRET_0 44b612097beeece79198b35a9599ea408fea42ec6200c5a5a531206af7caddc1 "
                        "b0141f92010ff97c70ea22f3be22d2dee948bd68db128750c32d1ddeccb197bd";
        (*sslkeylog) << "CLIENT_TRAFFIC_SECRET_0 44b612097beeece79198b35a9599ea408fea42ec6200c5a5a531206af7caddc1 "
                        "55ae7c492f9123f9f4241a4330298a4e90bf347e348c2f29a217abe7fda879b5";
        (*sslkeylog) << "SERVER_HANDSHAKE_TRAFFIC_SECRET 5c7f64c0b798e7b0d8142b51d26d69ad04aa212af7a650df688db819310970f0 "
                        "423f965b36fa8698b4b5c0e0d2fd834a84da7191adbf6e6f10c26f68d11516cb";
        (*sslkeylog) << "CLIENT_HANDSHAKE_TRAFFIC_SECRET 5c7f64c0b798e7b0d8142b51d26d69ad04aa212af7a650df688db819310970f0 "
                        "be05093a8d578daa4efdf051ab0fea471c6a182bffb0176931da5c9e445ebd7e";
        (*sslkeylog) << "EXPORTER_SECRET 5c7f64c0b798e7b0d8142b51d26d69ad04aa212af7a650df688db819310970f0 "
                        "e8c36075a474b8a43f833728bb8c2eeff55e85797354a8e5aeec84c983bba762";
        (*sslkeylog) << "SERVER_TRAFFIC_SECRET_0 5c7f64c0b798e7b0d8142b51d26d69ad04aa212af7a650df688db819310970f0 "
                        "920e7a9fd9d0788f6f45f2564be2e28defb2672f460bbdcfbad6256895c7b23e";
        (*sslkeylog) << "CLIENT_TRAFFIC_SECRET_0 5c7f64c0b798e7b0d8142b51d26d69ad04aa212af7a650df688db819310970f0 "
                        "fa396a936a9d64f804cb22c183003954ad30e15441c1b7bd532fd0eb4129c415";

        play_pcap(&session, pcap_tls13_http2_aes128gcm_sha256, sizeof_pcap_tls13_http2_aes128gcm_sha256);
    }

    {
        _test_case.begin("TLS 1.2 curl_http1_tls12.pcapng");

        tls_session session(session_type_tls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "CLIENT_RANDOM 9d430031eb9bdfbf49a5efcbf57582b8828fd1825772855f549c496025822b7d "
                        "44473b9ae5920d1a875a561d693bd3e010bcf1d970379bff3d6ec8a200158c395a4606305b61b9345462626a03110ed1";

        play_pcap(&session, pcap_curl_http1_tls12, sizeof_pcap_curl_http1_tls12);
    }
}
