/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *  see HTTP/2 Frame
 */

#include "sample.hpp"

//  test_payload_write
//  test_payload_read
//
//  type        size    endian      name        group
//  uint8       1       N/A         "padlen"    "pad"
//  binary_t    *       N/A         "data"      N/A
//  uint32      4       true        "value"     N/A
//  binary_t    *       N/A         "pad"       "pad"

void test_payload_write() {
    const OPTION& option = _cmdline->value();
    _test_case.begin("payload");

    payload pl;
    binary_t data = str2bin("data");
    binary_t pad = str2bin("pad");
    uint8 padlen = 3;  // "pad"
    basic_stream bs;
    binary_t bin_padded;
    binary_t bin_notpadded;

    pl << new payload_member(padlen, "padlen", "pad") << new payload_member(data, "data") << new payload_member((uint32)0x1000, true, "value")
       << new payload_member(pad, "pad", "pad");

    // enable "pad" group
    {
        pl.set_group("pad", true);
        pl.write(bin_padded);

        // test
        binary_t data;
        binary_t pad;
        auto padlen = pl.t_value_of<uint8>("padlen");
        auto value = pl.t_value_of<uint32>("value");
        pl.get_binary("data", data);
        pl.get_binary("pad", pad);
        _test_case.assert(3 == padlen, __FUNCTION__, "write #padlen");
        _test_case.assert(data == str2bin("data"), __FUNCTION__, "write #value");
        _test_case.assert(0x1000 == value, __FUNCTION__, "write #data");
        _test_case.assert(pad == str2bin("pad"), __FUNCTION__, "write #pad");
        _logger->hdump("padded", bin_padded, 16, 3);
        _test_case.assert(bin_padded == base16_decode_rfc("03 64 61 74 61 00 00 10 00 70 61 64"), __FUNCTION__,
                          R"(enable "pad" group)");  // 3 || "data" || 0x00001000 || "pad"
    }

    // disable "pad" group
    {
        pl.set_group("pad", false);
        pl.write(bin_notpadded);

        // test
        _logger->hdump("not padded", bin_notpadded, 16, 3);
        _test_case.assert(bin_notpadded == base16_decode_rfc("64 61 74 61 00 00 10 00"), __FUNCTION__, R"(disable "pad" group)");  // "data" || 0x00001000
    }
}

void test_payload_read() {
    const OPTION& option = _cmdline->value();
    _test_case.begin("payload");

    payload pl;
    binary_t bin_dump;
    binary_t decoded = base16_decode("036461746100001000706164");

    pl << new payload_member((uint8)0, "padlen", "pad") << new payload_member(binary_t(), "data") << new payload_member((uint32)0, true, "value")
       << new payload_member(binary_t(), "pad", "pad");
    pl.set_reference_value("pad", "padlen");  // length of "pad" is value of "padlen"

    // read
    {
        // pl << padlen(uint8:1) << data(unknown:?) << value(uint32:4) << pad(referenceof.padlen:?)
        //  input  : 036461746100001000706164
        //         : pl << padlen(uint8:1) << data(unknown:?) << value(uint32:4) << pad(referenceof.padlen:?)
        //  learn  :
        //         : pl.select("padlen")
        //         : pl << padlen(uint8:1) << data(unknown:?) << value(uint32:4) << pad(referenceof.padlen:3)
        //  infer  :
        //         : 12 - 1 - 4 - 3 = 12 - 8 = 4
        //         : pl << padlen(uint8:1) << data(unknown:4) << value(uint32:4) << pad(referenceof.padlen:3)
        //         : 03 64617461 00001000 706164
        //  result : padlen->3, data->"data", value->0x00001000, pad->"pad"
        pl.read(decoded);

        binary_t data;
        binary_t pad;
        auto padlen = pl.t_value_of<uint8>("padlen");
        auto value = pl.t_value_of<uint32>("value");
        pl.get_binary("data", data);
        pl.get_binary("pad", pad);
        _test_case.assert(3 == padlen, __FUNCTION__, "read #padlen");
        _test_case.assert(data == str2bin("data"), __FUNCTION__, "read #value");
        _test_case.assert(0x1000 == value, __FUNCTION__, "read #data");
        _test_case.assert(pad == str2bin("pad"), __FUNCTION__, "read #pad");
    }
    // write
    {
        pl.write(bin_dump);

        _logger->hdump("decoded", decoded, 16, 3);
        _logger->hdump("dump", bin_dump, 16, 3);
        _test_case.assert(bin_dump == decoded, __FUNCTION__, "read (contains one member of arbitrary size)");
    }
}

void test_uint24() {
    _test_case.begin("uint24");
    const char* sample = "00 03 28";
    binary_t bin = base16_decode_rfc(sample);

    uint32 ui32 = 0;
    b24_i32(&bin[0], bin.size(), ui32);
    _test_case.assert(0x0328 == ui32, __FUNCTION__, "b24_i32");

    byte_t buf[3];
    i32_b24(buf, 3, ui32);
    _test_case.assert(0 == memcmp(buf, &bin[0], 3), __FUNCTION__, "i32_b24");
}

//  test_payload_uint24
//
//  type        size    endian      name        group
//  uint8       1       N/A         "padlen"    N/A
//  uint24_t    3       N/A         "data"      N/A
//  uint32      4       true        "value"     N/A
//  binary_t    *       N/A         "pad"       N/A

void test_payload_uint24() {
    const OPTION& option = _cmdline->value();
    _test_case.begin("payload");

    binary_t pad = str2bin("pad");
    binary_t bin_payload;
    binary_t expect = base16_decode("0310000010000000706164");

    // write
    {
        payload pl;
        uint8 padlen = 3;  // "pad"
        basic_stream bs;
        uint24_t i32_24(0x100000);  // 32/24 [0 .. 0x00ffffff]
        uint32 i32 = 0x10000000;    // 32/32 [0 .. 0xffffffff]

        pl << new payload_member(padlen, "padlen") << new payload_member(i32_24, "int32_24") << new payload_member(i32, true, "int32_32")
           << new payload_member(pad, "pad");

        pl.write(bin_payload);

        // test
        _logger->hdump("uint24", bin_payload, 16, 3);
        _test_case.assert(expect == bin_payload, __FUNCTION__, "payload /w i32_b24");  // 3(1) || i32_24(3) || i32_32(4) || "pad"(3)
    }

    // read
    {
        payload pl;
        uint24_t i32_24;
        pl << new payload_member((uint8)0, "padlen") << new payload_member(i32_24, "int32_24") << new payload_member((uint32)0, true, "int32_32")
           << new payload_member(pad, "pad");

        pl.read(expect);

        // test
        uint8 padlen = pl.t_value_of<uint8>("padlen");
        uint32 i24_value = pl.t_value_of<uint32>("int32_24");
        uint32 i32 = pl.t_value_of<uint32>("int32_32");
        _logger->writeln("padlen %u uint32_24 %u (0x%08x) uint32_32 %u (0x%08x)", padlen, i24_value, i24_value, i32, i32);
        _test_case.assert(3 == padlen, __FUNCTION__, "read #padlen");
        _test_case.assert(0x100000 == i24_value, __FUNCTION__, "read #i32_b24");  // 3(1) || i32_24(3) || i32_32(4) || "pad"(3)

        binary_t bin_dump;
        pl.write(bin_dump);
        _test_case.assert(expect == bin_dump, __FUNCTION__, "payload /w i32_b24");  // 3(1) || i32_24(3) || i32_32(4) || "pad"(3)
    }
}

void test_group(const char* input, bool expect) {
    constexpr char constexpr_hdr[] = "hdr";
    constexpr char constexpr_len1[] = "len1";
    constexpr char constexpr_data1[] = "data1";
    constexpr char constexpr_group1[] = "group1";
    constexpr char constexpr_len2[] = "len2";
    constexpr char constexpr_data2[] = "data2";
    constexpr char constexpr_group2[] = "group2";

    binary_t bin = base16_decode_rfc(input);
    size_t pos = 0;

    bool cond_group2 = false;
    uint8 hdr = 0;
    uint16 len1 = 0;
    binary_t data1;
    uint16 len2 = 0;
    binary_t data2;
    binary_t dump_group1;
    binary_t dump_groups;
    binary_t dump_all;
    {
        payload pl;
        pl << new payload_member(uint8(0), constexpr_hdr)                            //
           << new payload_member(uint16(0), true, constexpr_len1, constexpr_group1)  // group1
           << new payload_member(binary_t(), constexpr_data1, constexpr_group1)      // group1
           << new payload_member(uint16(0), true, constexpr_len2, constexpr_group2)  // group2
           << new payload_member(binary_t(), constexpr_data2, constexpr_group2);     // group2
        // value(hdr)   group2
        //     01       enable
        //     00       disable
        auto lambda = [&](payload* pl, payload_member* member) -> void {
            auto hdr = pl->t_value_of<uint8>(member);
            pl->set_group(constexpr_group2, (0 != hdr));
        };
        pl.set_condition(constexpr_hdr, lambda);
        pl.set_reference_value(constexpr_data1, constexpr_len1);
        pl.set_reference_value(constexpr_data2, constexpr_len2);

        pl.read(&bin[0], bin.size(), pos);

        cond_group2 = pl.get_group_condition(constexpr_group2);

        hdr = pl.t_value_of<uint8>(constexpr_hdr);
        len1 = pl.t_value_of<uint16>(constexpr_len1);
        pl.get_binary(constexpr_data1, data1);

        if (cond_group2) {
            len2 = pl.t_value_of<uint16>(constexpr_len2);
            pl.get_binary(constexpr_data2, data2);
        }

        pl.write(dump_group1, {"group1"});         // write including "group1"
        pl.write(dump_all, {"group1", "group2"});  // write including "group1" and "group2"
    }
    {
        _logger->writeln("hdr %i", hdr);
        _logger->writeln("len1 %i", len1);
        _logger->dump(data1, 16, 3);
        if (cond_group2) {
            _logger->writeln("len2 %i", len2);
            _logger->dump(data2, 16, 3);
        }
        _logger->hdump("dump except group2", dump_group1, 16, 3);
        _logger->hdump("dump all", dump_all, 16, 3);
    }

    _test_case.assert(cond_group2 == expect, __FUNCTION__, "group");
}

void test_group() {
    _test_case.begin("group");
    // case.1
    // 00000000 : 01 00 05 64 61 74 61 31 00 05 64 61 74 61 32 -- | ...data1..data2
    // case.2
    // 00000000 : 00 00 05 64 61 74 61 31 -- -- -- -- -- -- -- -- | ...data1
    const char* case1 = "01 00 05 64 61 74 61 31 00 05 64 61 74 61 32";
    const char* case2 = "00 00 05 64 61 74 61 31";
    test_group(case1, true);
    test_group(case2, false);
}