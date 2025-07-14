/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *          RFC 9204 QPACK: Field Compression for HTTP/3
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

// test/quic/http3/http3.pcapng

struct testvector_qpack {
    int dir;
    uint32 type;
    const char* desc;
    const char* stream;
} tv[] = {
    {
        from_client,
        qpack_quic_stream_encoder,
        "#23 QPACK encoder stream",
        // QPACK encoder stream; 2 opcodes (2 total)
        //     QPACK encoder opcode: Set DTable Cap=4096
        //         Capacity: 4096
        //     QPACK encoder INSERT_INDEXED ref_len=1 ref=0 val_len=15
        //         Name Reference: c0
        //         Value: "www.google.com"
        //     QPACK encoder INSERT_INDEXED ref_len=2 ref=95 val_len=9
        //         Name Reference: ff20
        //         Value (Huffman): 25b650c3cb842b83
        //         Value: "curl/8.11.0"
        //     [QPACK encoder instruction count increment: 2]
        //     [QPACK encoder instruction count: 2]
        "3f e1 1f c0 0e 77 77 77 2e 67 6f 6f 67 6c 65 2e"
        "63 6f 6d ff 20 88 25 b6 50 c3 cb 84 2b 83",
    },
    {
        from_client,
        qpack_quic_stream_header,  // Frame Payload only
        "#24 HEADERS",
        // HEADERS len=8, GET /
        //     Type: HEADERS (0x0000000000000001)
        //     Length: 8
        //     Frame Payload: 0381d1d710c111dd
        //     [Header Length: 130]
        //     [Headers Count: 6]
        //     Header: :method: GET
        //     Header: :scheme: https
        //     Header: :authority: www.google.com
        //     Header: :path: /
        //     Header: user-agent: curl/8.11.0
        //     Header: accept: */*
        //     [Full request URI: https://www.google.com/]
        "03 81 d1 d7 10 c1 11 dd",
    },
};

void test_qpack_stream() {
    _test_case.begin("HTTP/3 QPACK STREAM");

    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    qpack_dynamic_table qpack_dyntable;
    for (auto item : tv) {
        auto bin = base16_decode_rfc(item.stream);
        size_t pos = 0;
        std::list<std::pair<std::string, std::string>> kv;
        ret = enc.decode(&qpack_dyntable, &bin[0], bin.size(), pos, kv, item.type);
        for (auto kvitem : kv) {
            _logger->writeln("%s: %s", kvitem.first.c_str(), kvitem.second.c_str());
        }
        _test_case.test(ret, __FUNCTION__, "%s", item.desc);
    }
}
