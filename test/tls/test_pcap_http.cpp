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
}
