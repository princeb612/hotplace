/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void test_huffman_codes() {
    return_t ret = errorcode_t::success;

    const char* sample = "We don't playing because we grow old; we grow old because we stop playing. - George Bernard Shaw";
    size_t samplesize = strlen(sample);
    std::map<uint8, std::string> table;

    huffman_coding huff;
    huff.load(sample).learn().infer();

    auto lambda_exports = [&](uint8 sym, const char* code) -> void {
        _logger->writeln("sym %c (0x%02x) code : %s (len %zi)", isprint(sym) ? sym : '?', sym, code, strlen(code));
        table.emplace(sym, code);
    };

    huff.exports(lambda_exports);

    // sym B (0x42) code : 1100010 (len 7)
    // sym G (0x47) code : 1100011 (len 7)
    // sym S (0x53) code : 1100100 (len 7)
    // sym W (0x57) code : 1100101 (len 7)
    // ...

    _test_case.assert("1100010" == table['B'], __FUNCTION__, "check the code for the symbol B");
    _test_case.assert("1100011" == table['G'], __FUNCTION__, "check the code for the symbol G");
    _test_case.assert("1100100" == table['S'], __FUNCTION__, "check the code for the symbol S");
    _test_case.assert("1100101" == table['W'], __FUNCTION__, "check the code for the symbol W");

    // 00000000 : CA FE EC 57 13 C8 21 5A 89 FC DE 90 59 BF 4F 9A | ...W..!Z....Y.O.
    // 00000010 : 5D 7B 0D E1 F4 F9 A5 D7 B0 DF CD E9 05 9B F4 FC | ]{..............
    // 00000020 : C9 72 F2 08 56 A2 78 3A FF 8D DA 1B F8 9A 0C 26 | .r..V.x:.......&
    // 00000030 : FE 45 A2 80 -- -- -- -- -- -- -- -- -- -- -- -- | .E..

    basic_stream ebs;
    ret = huff.encode(&ebs, sample, samplesize);
    _logger->writeln(ebs);

    binary_t enc;
    ret = huff.encode(enc, sample, samplesize);
    _logger->dump(enc);
    _test_case.test(ret, __FUNCTION__, "encode");

    _logger->writeln("before %zi -> after %zi (efficiency %.2f%%)", samplesize, enc.size(), enc.size() / (float)samplesize * 100);

    // manual decode (code len in bits < 5)
    // original 010110 1000 1010
    // storage  010110 1000 10100000

    basic_stream dbs;

    ret = huff.decode(&dbs, &enc[0], enc.size());
    _test_case.assert(success != ret, __FUNCTION__, "error detected");

    ret = huff.decode(&dbs, &enc[0], enc.size(), manual_decode);
    _test_case.test(ret, __FUNCTION__, "error ignored");

    dbs.resize(samplesize);
    _logger->writeln(dbs);
    _test_case.assert(dbs == sample, __FUNCTION__, "decode");
}
