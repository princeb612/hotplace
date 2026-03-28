#include "sample.hpp"

void test_bignumber() {
    _test_case.begin("bignumber");

    {
        bignumber a(1);
        a <<= 32;
        a.dump([](binary_t& bin) -> void {
            // debug
        });
    }

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
        std::string gcd;
    } table[] = {
        {"case 0", 36028797018963967LL, 1,                                                         //
         "36028797018963968", "36028797018963966", "36028797018963967", "36028797018963967", "0",  //
         "72057594037927934", "18014398509481983", "1"},
        {"case 1", 123456789012345678LL, 9876543210LL,                                                          //
         "123456798888888888", "123456779135802468", "1219326311248285312223746380", "12499999", "8763888888",  //
         "246913578024691356", "61728394506172839", "18"},
        {"case 2", -123456789012345678LL, -9876543210LL,                                                           //
         "-123456798888888888", "-123456779135802468", "1219326311248285312223746380", "12499999", "-8763888888",  //
         "-246913578024691356", "-61728394506172839", "-18"},
        {"case 3", 123456789012345678LL, -9876543210LL,                                                           //
         "123456779135802468", "123456798888888888", "-1219326311248285312223746380", "-12499999", "8763888888",  //
         "246913578024691356", "61728394506172839", "-18"},
        {"case 4", -123456789012345678LL, 9876543210LL,                                                              //
         "-123456779135802468", "-123456798888888888", "-1219326311248285312223746380", "-12499999", "-8763888888",  //
         "-246913578024691356", "-61728394506172839", "18"},
        {"case 5", 9876543210LL, 123456789012345678LL,                                                    //
         "123456798888888888", "-123456779135802468", "1219326311248285312223746380", "0", "9876543210",  //
         "19753086420", "4938271605", "18"},
        {"case 6", -9876543210LL, -123456789012345678LL,                                                   //
         "-123456798888888888", "123456779135802468", "1219326311248285312223746380", "0", "-9876543210",  //
         "-19753086420", "-4938271605", "-18"},
        {"case 7", -9876543210LL, 123456789012345678LL,                                                     //
         "123456779135802468", "-123456798888888888", "-1219326311248285312223746380", "0", "-9876543210",  //
         "-19753086420", "-4938271605", "-18"},
        {"case 8", 9876543210LL, -123456789012345678LL,                                                    //
         "-123456779135802468", "123456798888888888", "-1219326311248285312223746380", "0", "9876543210",  //
         "19753086420", "4938271605", "18"},
    };

    // https://www.calculator.net/big-number-calculator.html
    // mod : verified only positive big numbers

    for (auto item : table) {
        bignumber n1 = item.n1;
        bignumber n2 = item.n2;

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
        auto g = bignumber::gcd(n1, n2).str();
        _test_case.assert(g == item.gcd, __FUNCTION__, "%s gcd %s", item.text, g.c_str());
    }

    // modular
    {
        // -7 % 3 = -1, 7 % -3 = 1
        auto a = bignumber(-7) % bignumber(3);
        _logger->writeln("a = %s", a.str().c_str());
        _test_case.assert(a.str() == "-1", __FUNCTION__, "-7 mod 3");

        auto b = bignumber(7) % bignumber(-3);
        _logger->writeln("b = %s", b.str().c_str());
        _test_case.assert(b.str() == "1", __FUNCTION__, "7 mod -3");
    }

#ifndef __SIZEOF_INT128__
    {
        typedef bigint<128> int128;
        int128 a(9223372036854775807LL);
        int128 b(2147483647LL);
        int128 c;
        _logger->writeln("int128 a = %s", a.str().c_str());
        _logger->writeln("int128 b = %s", b.str().c_str());

        c = a + b;
        _test_case.assert(c.str() == "9223372039002259454", __FUNCTION__, "int128 a + b = %s", c.str().c_str());
        c = a - b;
        _test_case.assert(c.str() == "9223372034707292160", __FUNCTION__, "int128 a - b = %s", c.str().c_str());
        c = a * b;
        _test_case.assert(c.str() == "19807040619342712359383728129", __FUNCTION__, "int128 a * b = %s", c.str().c_str());
        c = a / b;
        _test_case.assert(c.str() == "4294967298", __FUNCTION__, "int128 a / b = %s", c.str().c_str());
    }
    {
        typedef bigint<128, false> uint128;
        uint128 a;
        a = (bignumber(1) << 64) - 1;  // 18446744073709551615LL (2^64 - 1)
        _logger->writeln("uint128 a = %s", a.str().c_str());
    }
#endif

    {
        typedef bigint<256> int256;
        int256 a(bignumber(1) << 128);  // 340282366920938463463374607431768211456
        int256 b(bignumber(1) << 64);   // 18446744073709551616
        int256 c;
        _logger->writeln("int256 a = %s", a.str().c_str());
        _logger->writeln("int256 b = %s", b.str().c_str());

        c = a + b;
        _test_case.assert(c.str() == "340282366920938463481821351505477763072", __FUNCTION__, "int256 a + b = %s", c.str().c_str());
        c = a - b;
        _test_case.assert(c.str() == "340282366920938463444927863358058659840", __FUNCTION__, "int256 a - b = %s", c.str().c_str());
        c = a * b;
        _test_case.assert(c.str() == "6277101735386680763835789423207666416102355444464034512896", __FUNCTION__, "int256 a * b = %s", c.str().c_str());
        c = a / b;
        _test_case.assert(c.str() == "18446744073709551616", __FUNCTION__, "int256 a / b = %s", c.str().c_str());
    }
}
