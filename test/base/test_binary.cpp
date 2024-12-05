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

void test_binary() {
    _test_case.begin("binary");
    binary_t bin;
    uint128 ui128 = 0;
    uint64 ui64 = 0;
    uint32 ui32 = 0;

    uint16 ui16 = 1;
    ui16 = convert_endian(ui16);
    binary_load(bin, sizeof(uint32), (byte_t *)&ui16, sizeof(ui16));
    // 4 bytes long
    // 00000000 : 00 00 00 01 -- -- -- -- -- -- -- -- -- -- -- -- | ....
    _logger->dump(bin);

    return_t ret = errorcode_t::success;
    ui32 = t_binary_to_integer<uint32>(bin, ret);
    _test_case.assert(1 == ui32, __FUNCTION__, "binary_to_integer #uint32");
    ui64 = t_binary_to_integer<uint64>(bin, ret);
    _test_case.assert(1 == ui64, __FUNCTION__, "binary_to_integer #uint64");
    ui128 = t_binary_to_integer<uint128>(bin, ret);
    _test_case.assert(1 == ui128, __FUNCTION__, "binary_to_integer #uint128");

    // narrow, truncate
    // 00000000 : 56 78 -- -- -- -- -- -- -- -- -- -- -- -- -- -- | Vx
    binary_t bin1;
    binary_t bin2;
    ui32 = 0x12345678;
    t_binary_load<uint32>(bin1, sizeof(uint16), ui32, hton32);
    t_binary_append2<uint32>(bin2, sizeof(uint16), ui32, hton32);
    ui16 = t_binary_to_integer<uint16>(bin1, ret);

    _logger->hdump("> binary_load (narrow)", bin1);
    _logger->hdump("> binary_append2 (narrow)", bin2);
    _test_case.assert(bin1 == base16_decode("0x5678"), __FUNCTION__, "binary_load (narrow)");
    _test_case.assert(bin2 == base16_decode("0x5678"), __FUNCTION__, "binary_append2 (narrow)");
    _test_case.assert(0x5678 == ui16, __FUNCTION__, "binary_to_integer #0x%04x", ui16);

    bin2.clear();

    // wide
    // 00000000 : 00 00 00 00 12 34 56 78 -- -- -- -- -- -- -- -- | .....4Vx
    t_binary_load<uint32>(bin1, sizeof(uint64), ui32, hton32);
    t_binary_append2<uint32>(bin2, sizeof(uint64), ui32, hton32);
    ui64 = t_binary_to_integer<uint64>(bin1, ret);

    _logger->hdump("> binary_load (wide)", bin1);
    _logger->hdump("> binary_append2 (wide)", bin2);
    _test_case.assert(bin1 == base16_decode("0x0000000012345678"), __FUNCTION__, "binary_load (wide)");
    _test_case.assert(bin2 == base16_decode("0x0000000012345678"), __FUNCTION__, "binary_append2 (wide)");
    _test_case.assert(0x12345678 == ui64, __FUNCTION__, "binary_to_integer #0x%I64x", ui64);

    bin2.clear();

    // wide
    // 00000000 : 00 00 00 00 00 00 00 00 00 00 00 00 12 34 56 78 | .............4Vx
    t_binary_load<uint32>(bin1, sizeof(uint128), ui32, hton32);
    t_binary_append2<uint32>(bin2, sizeof(uint128), ui32, hton32);
    ui128 = t_binary_to_integer<uint128>(bin1, ret);
    _logger->hdump("> binary_load (wide)", bin1);
    _logger->hdump("> binary_append2 (wide)", bin2);
    _test_case.assert(bin1 == base16_decode("0x00000000000000000000000012345678"), __FUNCTION__, "binary_load (wide)");
    _test_case.assert(bin2 == base16_decode("0x00000000000000000000000012345678"), __FUNCTION__, "binary_append2 (wide)");
    _test_case.assert(0x12345678 == ui128, __FUNCTION__, "binary_to_integer #0x%I128x", ui128);

    bin.clear();
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
