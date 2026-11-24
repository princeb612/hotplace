/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_binary.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/base/sample.hpp>

void test_binary1() {
    _test_case.begin("binary");
    binary_t bin;
#ifdef __SIZEOF_INT128__
    uint128 ui128 = 0;
#endif
    uint64 ui64 = 0;
    uint32 ui32 = 0;

    uint16 ui16 = 1;
    ui16 = convert_endian(ui16);
    binary_load(bin, sizeof(uint32), (byte_t*)&ui16, sizeof(ui16));
    // 4 bytes long
    // 00000000 : 00 00 00 01 -- -- -- -- -- -- -- -- -- -- -- -- | ....
    _logger->dump(bin);

    return_t ret = errorcode_t::success;
    ui32 = t_binary_to_integer<uint32>(bin, ret);
    _test_case.assert(1 == ui32, __FUNCTION__, "binary_to_integer #uint32");
    ui64 = t_binary_to_integer<uint64>(bin, ret);
    _test_case.assert(1 == ui64, __FUNCTION__, "binary_to_integer #uint64");
#ifdef __SIZEOF_INT128__
    ui128 = t_binary_to_integer<uint128>(bin, ret);
    _test_case.assert(1 == ui128, __FUNCTION__, "binary_to_integer #uint128");
#endif

    // narrow, truncate
    // 00000000 : 56 78 -- -- -- -- -- -- -- -- -- -- -- -- -- -- | Vx
    binary_t bin1;
    binary_t bin2;
    ui32 = 0x12345678;
    binary_load(bin1, sizeof(uint16), ui32, hton32);
    binary_append_n(bin2, sizeof(uint16), ui32, hton32);
    ui16 = t_binary_to_integer<uint16>(bin1, ret);

    _logger->hdump("> binary_load (narrow)", bin1);
    _logger->hdump("> binary_append2 (narrow)", bin2);
    _test_case.assert(bin1 == base16_decode("0x5678"), __FUNCTION__, "binary_load (narrow)");
    _test_case.assert(bin2 == base16_decode("0x5678"), __FUNCTION__, "binary_append2 (narrow)");
    _test_case.assert(0x5678 == ui16, __FUNCTION__, "binary_to_integer #0x%04x", ui16);

    bin2.clear();

    // wide
    // 00000000 : 00 00 00 00 12 34 56 78 -- -- -- -- -- -- -- -- | .....4Vx
    binary_load(bin1, sizeof(uint64), ui32, hton32);
    binary_append_n(bin2, sizeof(uint64), ui32, hton32);
    ui64 = t_binary_to_integer<uint64>(bin1, ret);

    _logger->hdump("> binary_load (wide)", bin1);
    _logger->hdump("> binary_append2 (wide)", bin2);
    _test_case.assert(bin1 == base16_decode("0x0000000012345678"), __FUNCTION__, "binary_load (wide)");
    _test_case.assert(bin2 == base16_decode("0x0000000012345678"), __FUNCTION__, "binary_append2 (wide)");
    _test_case.assert(0x12345678 == ui64, __FUNCTION__, "binary_to_integer #0x%I64x", ui64);

    bin2.clear();

#ifdef __SIZEOF_INT128__
    // wide
    // 00000000 : 00 00 00 00 00 00 00 00 00 00 00 00 12 34 56 78 | .............4Vx
    binary_load(bin1, sizeof(uint128), ui32, hton32);
    binary_append_n(bin2, sizeof(uint128), ui32, hton32);
    ui128 = t_binary_to_integer<uint128>(bin1, ret);
    _logger->hdump("> binary_load (wide)", bin1);
    _logger->hdump("> binary_append2 (wide)", bin2);
    _test_case.assert(bin1 == base16_decode("0x00000000000000000000000012345678"), __FUNCTION__, "binary_load (wide)");
    _test_case.assert(bin2 == base16_decode("0x00000000000000000000000012345678"), __FUNCTION__, "binary_append2 (wide)");
    _test_case.assert(0x12345678 == ui128, __FUNCTION__, "binary_to_integer #0x%I128x", ui128);
    bin.clear();
#endif

    binary_append(bin, uint32(1), hton32);
    ui32 = t_binary_to_integer<uint32>(bin);
    _test_case.assert(1 == ui32, __FUNCTION__, "bin32 to uint32 %u", ui32);

    bin.clear();
    binary_append(bin, uint32(1), hton32);
    ui64 = t_binary_to_integer<uint64>(bin);
    _test_case.assert(1 == ui64, __FUNCTION__, "bin32 to uint64 %I64u", ui64);

    bin.clear();
    binary_append(bin, uint8(1));
    ui32 = t_binary_to_integer<uint32>(bin);
    _test_case.assert(1 == ui32, __FUNCTION__, "bin8 to uint32 %u", ui32);
}

void test_binary2() {
    _test_case.begin("binary");

    binary_t bin1;
    binary_append(bin1, uint16(32768));  // wo endian_transformer
    std::string str1;
    base16_encode(bin1, str1);
    _test_case.assert(str1 == "0080", __FUNCTION__, "%s", str1.c_str());

    binary_t bin2;
    binary_append(bin2, uint16(32768), [](uint16 v) -> uint16 { return hton16(v); });  // lambda
    std::string str2;
    base16_encode(bin2, str2);
    _test_case.assert(str2 == "8000", __FUNCTION__, "%s", str2.c_str());
}

void test_binaries_moveto() {
    _test_case.begin("binaries");

    t_binaries<uint32, uint8> bins;
    const byte_t first[] = {0x11};
    const byte_t third[] = {0x33};

    // A reserved entry's tag and keep-entry policy move with the entry.
    bins.reserve(1, 0x51);
    bins.write(1, 0, first, sizeof(first));
    bins.write(1, 3, third, sizeof(third));
    _test_case.assert(true == bins.is_fragmented(1), __FUNCTION__, "source entry is fragmented");

    return_t ret = bins.moveto(1, 2);
    _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "move to an unused id");
    _test_case.assert(false == bins.exist(1), __FUNCTION__, "source id is removed");
    _test_case.assert(true == bins.exist(2), __FUNCTION__, "destination id exists");
    _test_case.assert(true == bins.is_fragmented(2), __FUNCTION__, "fragment metadata moves");
    uint8 tag = 0;
    ret = bins.get_tag(2, tag);
    _test_case.assert((errorcode_t::success == ret) && (0x51 == tag), __FUNCTION__, "entry tag moves");
    binary_t actual;
    ret = bins.peek(2, actual);
    _test_case.assert((errorcode_t::success == ret) && (4 == actual.size()) && (0x11 == actual[0]) && (0x00 == actual[1]) && (0x00 == actual[2]) && (0x33 == actual[3]),
                      __FUNCTION__, "entry bytes move");
    bins.erase(2);
    _test_case.assert(true == bins.exist(2), __FUNCTION__, "bin_keep_entry moves to destination");
    ret = bins.peek(2, actual);
    _test_case.assert((errorcode_t::success == ret) && actual.empty(), __FUNCTION__, "erase clears moved reservation");

    // Moving onto an existing id replaces the complete destination entry.
    binary_t old_value;
    binary_t new_value;
    binary_append(old_value, byte_t(0xaa));
    binary_append(new_value, byte_t(0xbb));
    bins.assign(3, old_value);
    bins.set_tag(3, 0x31);
    bins.assign(4, new_value);
    bins.set_tag(4, 0x42);
    ret = bins.moveto(4, 3);
    _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "move replaces an existing destination");
    ret = bins.peek(3, actual);
    _test_case.assert((errorcode_t::success == ret) && (actual == new_value), __FUNCTION__, "source payload replaces destination payload");
    ret = bins.get_tag(3, tag);
    _test_case.assert((errorcode_t::success == ret) && (0x42 == tag), __FUNCTION__, "source tag replaces destination tag");
    _test_case.assert(false == bins.exist(4), __FUNCTION__, "replaced source id is removed");

    ret = bins.moveto(3, 3);
    _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "same-id move is a no-op");
    ret = bins.moveto(9, 10);
    _test_case.assert(errorcode_t::not_found == ret, __FUNCTION__, "missing source is reported");
    _test_case.assert(false == bins.exist(10), __FUNCTION__, "missing source does not create destination");
}

void testcase_binary() {
    test_binary1();
    test_binary2();
    test_binaries_moveto();
}
