/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_bignumber.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_bn1() {
    _test_case.begin("bignumber");
    struct testvector {
        const char* hexvalue;
        std::string decvalue;
    } table[] = {
        {"0x123456789abcdef", "81985529216486895"},
        {"0x123456789", "4886718345"},
        {"0x8000", "32768"},
        // bignumber from numeric string (greater than int128)
        // uint128.max + 1
        {"0x100000000000000000000000000000000", "340282366920938463463374607431768211456"},
        // 2^256 - 1
        {"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "115792089237316195423570985008687907853269984665640564039457584007913129639935"},
    };

    bignumber bn1;
    bignumber bn2;

    for (const auto& item : table) {
        bn1 = item.hexvalue;
        bn2 = item.decvalue;

        bn1.dump([&](const binary_t& bin) -> void { _logger->hdump("from hexvalue", bin, 16, 3); });
        bn2.dump([&](const binary_t& bin) -> void { _logger->hdump("from decvalue", bin, 16, 3); });

        _test_case.assert(bn1 == bn2, __FUNCTION__, "compare");
        _test_case.assert(bn1.str() == item.decvalue, __FUNCTION__, "base16 %s", item.decvalue.c_str());
    }
}

void test_bn2() {
    _test_case.begin("bignumber");
    struct {
        const char* text;
        int64 n1;
        int64 n2;
        std::string add;
        std::string sub;
        std::string mul;
        std::string div;
        std::string mod;
        std::string lshift1;
        std::string rshift1;
    } table[] = {
        {"case 0", 36028797018963967LL, 1, "36028797018963968", "36028797018963966", "36028797018963967", "36028797018963967", "0", "72057594037927934",
         "18014398509481983"},
        {"case 1", 123456789012345678LL, 9876543210LL, "123456798888888888", "123456779135802468", "1219326311248285312223746380", "12499999", "8763888888",
         "246913578024691356", "61728394506172839"},
        {"case 2", -123456789012345678LL, -9876543210LL, "-123456798888888888", "-123456779135802468", "1219326311248285312223746380", "12499999", "-8763888888",
         "-246913578024691356", "-61728394506172839"},
        {"case 3", 123456789012345678LL, -9876543210LL, "123456779135802468", "123456798888888888", "-1219326311248285312223746380", "-12499999", "8763888888",
         "246913578024691356", "61728394506172839"},
        {"case 4", -123456789012345678LL, 9876543210LL, "-123456779135802468", "-123456798888888888", "-1219326311248285312223746380", "-12499999", "-8763888888",
         "-246913578024691356", "-61728394506172839"},
        {"case 5", 9876543210LL, 123456789012345678LL, "123456798888888888", "-123456779135802468", "1219326311248285312223746380", "0", "9876543210", "19753086420",
         "4938271605"},
        {"case 6", -9876543210LL, -123456789012345678LL, "-123456798888888888", "123456779135802468", "1219326311248285312223746380", "0", "-9876543210", "-19753086420",
         "-4938271605"},
        {"case 7", -9876543210LL, 123456789012345678LL, "123456779135802468", "-123456798888888888", "-1219326311248285312223746380", "0", "-9876543210", "-19753086420",
         "-4938271605"},
        {"case 8", 9876543210LL, -123456789012345678LL, "-123456779135802468", "123456798888888888", "-1219326311248285312223746380", "0", "9876543210", "19753086420",
         "4938271605"},
    };

    // mod : verified only positive big numbers

    for (auto item : table) {
        bignumber n1(item.n1);
        bignumber n2(item.n2);

#ifdef __SIZEOF_INT128__
        // gcc verification
        int128 v1 = item.n1;
        int128 v2 = item.n2;
        int128 add128 = v1 + v2;
        _test_case.assert(add128 == t_atoi<int128>(item.add), __FUNCTION__, "%s add %I128i", item.text, add128);
        int128 sub128 = v1 - v2;
        _test_case.assert(sub128 == t_atoi<int128>(item.sub), __FUNCTION__, "%s sub %I128i", item.text, sub128);
        int128 mul128 = v1 * v2;
        _test_case.assert(mul128 == t_atoi<int128>(item.mul), __FUNCTION__, "%s mul %I128i", item.text, mul128);
        int128 div128 = v1 / v2;
        _test_case.assert(div128 == t_atoi<int128>(item.div), __FUNCTION__, "%s div %I128i", item.text, div128);
        int128 mod128 = v1 % v2;
        _test_case.assert(mod128 == t_atoi<int128>(item.mod), __FUNCTION__, "%s mod %I128i", item.text, mod128);
        int128 lshift128 = v1 << 1;
        _test_case.assert(lshift128 == t_atoi<int128>(item.lshift1), __FUNCTION__, "%s lshift1 %I128i", item.text, lshift128);
        int128 rshift128 = v1 >> 1;
        _test_case.assert(rshift128 == t_atoi<int128>(item.rshift1), __FUNCTION__, "%s rshift1 %I128i", item.text, rshift128);
#endif

        auto add = (n1 + n2).str();
        _test_case.assert(add == item.add, __FUNCTION__, "%s add %s", item.text, add.c_str());
        auto sub = (n1 - n2).str();
        _test_case.assert(sub == item.sub, __FUNCTION__, "%s sub %s", item.text, sub.c_str());
        auto mul = (n1 * n2).str();
        _test_case.assert(mul == item.mul, __FUNCTION__, "%s mul %s", item.text, mul.c_str());
        auto div = (n1 / n2).str();
        _test_case.assert(div == item.div, __FUNCTION__, "%s div %s", item.text, div.c_str());
        auto mod = (n1 % n2).str();
        _test_case.assert(mod == item.mod, __FUNCTION__, "%s mod %s", item.text, mod.c_str());
        auto lshift1 = (n1 << 1).str();
        _test_case.assert(lshift1 == item.lshift1, __FUNCTION__, "%s lshift1 %s", item.text, lshift1.c_str());
        auto rshift1 = (n1 >> 1).str();
        _test_case.assert(rshift1 == item.rshift1, __FUNCTION__, "%s rshift1 %s", item.text, rshift1.c_str());
    }

#ifdef __SIZEOF_INT128__
    openssl_prng prng;
    int loop = 10;
    while (loop--) {
        int128 i1 = prng.rand64();
        int128 i2 = prng.rand64();
        int128 i = 0;
        bignumber b1 = i1;
        bignumber b2 = i2;
        bignumber bn;
        basic_stream bs;
        binary_t bin;
        std::string b16str;

        bs.clear();
        i = i1 + i2;
        bn = b1 + b2;
        bs.printf("%I128i", i);
        _test_case.assert(bs == bn.str(), __FUNCTION__, "%I128i + %I128i = %s (expect %I128i)", i1, i2, bn.str().c_str(), i);

        bs.clear();
        i = i1 - i2;
        bn = b1 - b2;
        bs.printf("%I128i", i);
        _test_case.assert(bs == bn.str(), __FUNCTION__, "%I128i - %I128i = %s (expect %I128i)", i1, i2, bn.str().c_str(), i);

        bs.clear();
        i = i1 * i2;
        bn = b1 * b2;
        bs.printf("%I128i", i);
        _test_case.assert(bs == bn.str(), __FUNCTION__, "%I128i * %I128i = %s (expect %I128i)", i1, i2, bn.str().c_str(), i);

        bs.clear();
        i = i1 / i2;
        bn = b1 / b2;
        bs.printf("%I128i", i);
        _test_case.assert(bs == bn.str(), __FUNCTION__, "%I128i / %I128i = %s (expect %I128i)", i1, i2, bn.str().c_str(), i);

        bs.clear();
        i = i1 % i2;
        bn = b1 % b2;
        bs.printf("%I128i", i);
        _test_case.assert(bs == bn.str(), __FUNCTION__, "%I128i %% %I128i = %s (expect %I128i)", i1, i2, bn.str().c_str(), i);
    }
#endif

    {
        bignumber a(int64(9223372036854775807));
        bignumber b(int64(2147483647));
        bignumber c;
        _logger->writeln("bignumber a = %s", a.str().c_str());
        _logger->writeln("bignumber b = %s", b.str().c_str());

        c = a + b;
        _test_case.assert(c.str() == "9223372039002259454", __FUNCTION__, "bignumber a + b = %s", c.str().c_str());
        c = a - b;
        _test_case.assert(c.str() == "9223372034707292160", __FUNCTION__, "bignumber a - b = %s", c.str().c_str());
        c = a * b;
        _test_case.assert(c.str() == "19807040619342712359383728129", __FUNCTION__, "bignumber a * b = %s", c.str().c_str());
        c = a / b;
        _test_case.assert(c.str() == "4294967298", __FUNCTION__, "bignumber a / b = %s", c.str().c_str());
    }

    // modular
    {
        // -7 % 3 = -1, 7 % -3 = 1
        auto a = bignumber(-7) % bignumber(3);
        _logger->writeln("a = %s", a.str().c_str());
        _test_case.assert(a.str() == "-1", __FUNCTION__, "-7 %% 3");

        auto b = bignumber(7) % bignumber(-3);
        _logger->writeln("b = %s", b.str().c_str());
        _test_case.assert(b.str() == "1", __FUNCTION__, "7 %% -3");
    }
}

void test_bn3() {
    _test_case.begin("bignumber");
    struct testvector {
        int bits;
        const char* minvalue;
        const char* maxvalue;
        const char* umaxvalue;  // 0 ~ umaxvalue
    } table[] = {
        {8, "-128", "127", "255"},
        {16, "-32768", "32767", "65535"},
        {32, "-2147483648", "2147483647", "4294967295"},
        {64, "-9223372036854775808", "9223372036854775807", "18446744073709551615"},
        {128, "-170141183460469231731687303715884105728", "170141183460469231731687303715884105727", "340282366920938463463374607431768211455"},
    };

    for (auto item : table) {
        bignumber intmin = -(bignumber(1) << (item.bits - 1));
        bignumber intmax = (bignumber(1) << (item.bits - 1)) - bignumber(1);
        bignumber uintmax = (bignumber(1) << item.bits) - bignumber(1);

        _logger->writeln([&](basic_stream& bs) -> void { bs << "int" << item.bits << ".min -2^" << (item.bits - 1); });
        _logger->writeln([&](basic_stream& bs) -> void { bs << "int" << item.bits << ".min 0x" << intmin.hex(); });
        _logger->writeln([&](basic_stream& bs) -> void { bs << "int" << item.bits << ".min " << intmin.str(); });

        _logger->writeln([&](basic_stream& bs) -> void { bs << "int" << item.bits << ".max 2^" << (item.bits - 1) << "-1"; });
        _logger->writeln([&](basic_stream& bs) -> void { bs << "int" << item.bits << ".max 0x" << intmax.hex(); });
        _logger->writeln([&](basic_stream& bs) -> void { bs << "int" << item.bits << ".max " << intmax.str(); });
        auto test = (intmin.str() == std::string(item.minvalue)) && (intmax.str() == std::string(item.maxvalue));
        _test_case.assert(test, __FUNCTION__, "check int%i.min ~ int%i.max", item.bits, item.bits);

        _logger->writeln([&](basic_stream& bs) -> void { bs << "uint" << item.bits << ".max 2^" << item.bits << "-1"; });
        _logger->writeln([&](basic_stream& bs) -> void { bs << "uint" << item.bits << ".max 0x" << uintmax.hex(); });
        _logger->writeln([&](basic_stream& bs) -> void { bs << "uint" << item.bits << ".max " << uintmax.str(); });
        auto utest = (uintmax.str() == std::string(item.umaxvalue));
        _test_case.assert(utest, __FUNCTION__, "check uint%i.max", item.bits);
    }

    {
        bignumber a(bignumber(1) << 128);  // 340282366920938463463374607431768211456
        bignumber b(bignumber(1) << 64);   // 18446744073709551616
        bignumber c;
        _logger->writeln("bignumber a = %s", a.str().c_str());
        _logger->writeln("bignumber b = %s", b.str().c_str());

        c = a + b;
        _test_case.assert(c.str() == "340282366920938463481821351505477763072", __FUNCTION__, "bignumber a + b = %s", c.str().c_str());
        c = a - b;
        _test_case.assert(c.str() == "340282366920938463444927863358058659840", __FUNCTION__, "bignumber a - b = %s", c.str().c_str());
        c = a * b;
        _test_case.assert(c.str() == "6277101735386680763835789423207666416102355444464034512896", __FUNCTION__, "bignumber a * b = %s", c.str().c_str());
        c = a / b;
        _test_case.assert(c.str() == "18446744073709551616", __FUNCTION__, "bignumber a / b = %s", c.str().c_str());

        openssl_prng prng;
        int loop = 10;
        while (loop--) {
            bignumber b1 = prng.rand64();
            bignumber b2 = prng.rand64();
            bignumber i = uint64(0);
            bignumber v = uint64(0);
            i = b1 + b2;
            _logger->writeln("%s + %s = %s", b1.str().c_str(), b2.str().c_str(), i.str().c_str());
            i = b1 - b2;
            _logger->writeln("%s - %s = %s", b1.str().c_str(), b2.str().c_str(), i.str().c_str());
            i = b1 * b2;
            _logger->writeln("%s * %s = %s", b1.str().c_str(), b2.str().c_str(), i.str().c_str());
            i = b1 / b2;
            _logger->writeln("%s / %s = %s", b1.str().c_str(), b2.str().c_str(), i.str().c_str());
            i = b1 % b2;
            _logger->writeln("%s %% %s = %s", b1.str().c_str(), b2.str().c_str(), i.str().c_str());
        }
    }
}

void test_bn4() {
    _test_case.begin("bignumber");
    struct testvector {
        uint64 i1;
        uint64 i2;
    } table[]{
        {0xc4fe9903b76d6c72ULL, 0x8e6781062bd05a82ULL}, {0xe8556865b15e621ULL, 0x894da65e198e0e8bULL}, {0x5dd523de7ca877ecULL, 0xe2c900ef8c975e5cULL},
        {0x1a72c958dda70797ULL, 0xbbaf38760fb4ff55ULL}, {0xb6a22bb40f07c9a0ULL, 0xd2c5ab685c2dcb4ULL}, {0xdc5c66b4bfb3312fULL, 0xb3c5b881db04af9bULL},
        {0x8ee394be324ce02fULL, 0x93d8c0e7925e2833ULL},
    };
    openssl_prng prng;
    for (const auto& item : table) {
        bignumber b1;
        bignumber b2;

        b1 = item.i1;
        b2 = item.i2;

        auto bit_and = item.i1 & item.i2;
        auto bit_or = item.i1 | item.i2;
        auto bit_xor = item.i1 ^ item.i2;

        auto bn_and = b1 & b2;
        auto bn_or = b1 | b2;
        auto bn_xor = b1 ^ b2;

        _test_case.assert(bignumber(bit_and) == bn_and, __FUNCTION__, "%I64x AND %I64x = %I64x (%s)", item.i1, item.i2, bit_and, bn_and.hex().c_str());
        _test_case.assert(bignumber(bit_or) == bn_or, __FUNCTION__, "%I64x OR %I64x = %I64x (%s)", item.i1, item.i2, bit_or, bn_or.hex().c_str());
        _test_case.assert(bignumber(bit_xor) == bn_xor, __FUNCTION__, "%I64x XOR %I64x = %I64x (%s)", item.i1, item.i2, bit_xor, bn_xor.hex().c_str());
    }

    {
        uint64 i1 = 0;
        uint64 i2 = 0;
        uint64 ir = 0;
        bignumber b1;
        bignumber b2;
        bignumber br;
        int loop = 10;

        while (loop--) {
            i1 = prng.rand64();
            i2 = prng.rand64();
            b1 = i1;
            b2 = i2;

            _logger->writeln("sample %I64x %I64x", i1, i2);

            ir = i1 & i2;
            br = b1 & b2;
            _logger->writeln("%I64x & %I64x = %s (expected %I64x)", i1, i2, br.hex().c_str(), ir);
            _test_case.assert(bignumber(ir) == br, __FUNCTION__, "%I64x & %I64x = %I64x (%s)", i1, i2, ir, br.hex().c_str());

            ir = i1 | i2;
            br = b1 | b2;
            _logger->writeln("%I64x | %I64x = %s (expected %I64x)", i1, i2, br.hex().c_str(), ir);
            _test_case.assert(bignumber(ir) == br, __FUNCTION__, "%I64x | %I64x = %I64x (%s)", i1, i2, ir, br.hex().c_str());

            ir = i1 ^ i2;
            br = b1 ^ b2;
            _logger->writeln("%I64x ^ %I64x = %s (expected %I64x)", i1, i2, br.hex().c_str(), ir);
            _test_case.assert(bignumber(ir) == br, __FUNCTION__, "%I64x ^ %I64x = %I64x (%s)", i1, i2, ir, br.hex().c_str());
        }
    }
}

void test_bn5() {
    _test_case.begin("bignumber");
    std::string sample = std::string("0x0123456789abcdef0123456789abcdef");
#ifdef __SIZEOF_INT128__
    int128 signed_sample = t_htoi<int128>(sample.c_str());
    uint128 unsigned_sample = t_htoi<uint128>(sample.c_str());
#else
    int64 signed_sample = t_htoi<int64>(sample.c_str());
    uint64 unsigned_sample = t_htoi<uint64>(sample.c_str());
#endif
    bignumber bn(sample);

    auto i8 = bn.t_bntoi<int8>();
    _logger->writeln("int8 %i", i8);
    _test_case.assert(i8 == int8(signed_sample), __FUNCTION__, "to.int8 %i", int8(signed_sample));

    auto ui8 = bn.t_bntoi<uint8>();
    _logger->writeln("uint8 %u", ui8);
    _test_case.assert(ui8 == uint8(unsigned_sample), __FUNCTION__, "to.uint8 %u", uint8(unsigned_sample));

    auto i16 = bn.t_bntoi<int16>();
    _logger->writeln("int16 %i", i16);
    _test_case.assert(i16 == int16(signed_sample), __FUNCTION__, "to.int16 %i", int16(signed_sample));

    auto ui16 = bn.t_bntoi<uint16>();
    _logger->writeln("uint16 %u", ui16);
    _test_case.assert(ui16 == uint16(unsigned_sample), __FUNCTION__, "to.uint16 %u", uint16(unsigned_sample));

    auto i32 = bn.t_bntoi<int32>();
    _logger->writeln("int32 %i", i32);
    _test_case.assert(i32 == int32(signed_sample), __FUNCTION__, "to.int32 %i", int32(signed_sample));

    auto ui32 = bn.t_bntoi<uint32>();
    _logger->writeln("uint32 %u", ui32);
    _test_case.assert(ui32 == uint32(unsigned_sample), __FUNCTION__, "to.uint32 %u", uint32(unsigned_sample));

    auto i64 = bn.t_bntoi<int64>();
    _logger->writeln("int64 %I64i", i64);
    _test_case.assert(i64 == int64(signed_sample), __FUNCTION__, "to.int64 %I64i", int64(signed_sample));

    auto ui64 = bn.t_bntoi<uint64>();
    _logger->writeln("uint64 %I64u", ui64);
    _test_case.assert(ui64 == uint64(unsigned_sample), __FUNCTION__, "to.uint64 %I64u", uint64(unsigned_sample));

#ifdef __SIZEOF_INT128__
    auto i128 = bn.t_bntoi<int128>();
    _logger->writeln("int128 %I128i", i128);
    _test_case.assert(i128 == int128(signed_sample), __FUNCTION__, "to.int128 %I64i", signed_sample);

    auto ui128 = bn.t_bntoi<uint128>();
    _logger->writeln("uint128 %I128u", ui128);
    _test_case.assert(ui128 == uint128(unsigned_sample), __FUNCTION__, "to.uint128 %I64u", signed_sample);
#endif
}

void test_bn6() {
    _test_case.begin("bignumber");
    bignumber bn(1);
    bignumber bn2;
    bn = -bn;
    _logger->writeln("bignumber = %s", bn.str().c_str());
    _test_case.assert(bn == -1, __FUNCTION__, "bignumber = -1");

    bn = "0xffffffffffffffff";  // uint64.max
    bn = -bn;
    bn2 = "-18446744073709551615";
    _logger->writeln("bignumber = %s", bn.str().c_str());
    _test_case.assert(bn == bn2, __FUNCTION__, "bignumber = -uint64.max");

    bn = "0xffffffffffffffffffffffffffffffff";  // uint128.max
    bn = -bn;
    bn2 = "-340282366920938463463374607431768211455";
    _logger->writeln("bignumber = %s", bn.str().c_str());
    _test_case.assert(bn == bn2, __FUNCTION__, "bignumber = -uint128.max");
}

void test_bn7() {
    _test_case.begin("bignumber");
    openssl_prng prng;
    int loop = 10;
    while (--loop) {
        uint64 i = prng.rand64();
        _logger->writeln("i = %I64u", i);
        bignumber bn(i);
        bn *= bn;
        _logger->writeln("i^i %s", bn.str().c_str());
        bn.sqrt();
        _logger->writeln("sqrt %s", bn.str().c_str());
        _test_case.assert(bn == i, __FUNCTION__, "square, sqrt %I64u", i);
    }
    {
        // https://en.wikipedia.org/wiki/Modular_exponentiation
        // c ≡ 4^13 (mod 497)
        // c is determined to be 445
        struct testvector {
            uint64 base;
            uint64 exp;
            uint64 m;
            uint64 expect;
        } table[] = {
            {4, 1, 497, 4},   {4, 2, 497, 16},  {4, 3, 497, 64},   {4, 4, 497, 256},  {4, 5, 497, 30},   {4, 6, 497, 120},  {4, 7, 497, 480},
            {4, 8, 497, 429}, {4, 9, 497, 225}, {4, 10, 497, 403}, {4, 11, 497, 121}, {4, 12, 497, 484}, {4, 13, 497, 445},
        };
        for (const auto& item : table) {
            auto bn = bignumber::modpow(item.base, item.exp, item.m);
            _test_case.assert(bn == item.expect, __FUNCTION__, "%I64u ^ %I64u %% %I64u = %s", item.base, item.exp, item.m, bn.str().c_str());
        }
    }
    {
        auto bn = bignumber::modinv(42, 2017);
        _test_case.assert(bn == 1969, __FUNCTION__, "modinv");
    }
}

void testcase_bignumber() {
    test_bn1();  // numeric, hexdecimal string
    test_bn2();  // + - * /
    test_bn3();  // shift
    test_bn4();  // AND OR XOR
    test_bn5();  // bn to integer
    test_bn6();  // neg
    test_bn7();  // sqaure, sqrt, modpow
}
