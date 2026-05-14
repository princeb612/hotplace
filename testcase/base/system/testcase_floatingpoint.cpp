/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_floatingpoint.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_floating_point() {
    _test_case.begin("floating point");
    rational_float fp;

    decimal_float d1(1, -1);  // 0.1
    decimal_float d2(2, -1);  // 0.2
    rational_float r1(1, 2);  // 1/2=0.5
    rational_float r2(1, 3);  // 1/3=0.333333...
    enum op {
        op_add = 1,
        op_sub = 2,
        op_mult = 3,
        op_div = 4,
    };

    auto lambda = [&](floating_point a, floating_point b, int op, floating_point expect) -> void {
        valist va;
        basic_stream fmt;
        basic_stream bs;
        floating_point res;

        fmt << "{1}";
        switch (op) {
            case op_add:
                fmt << " + ";
                res = a + b;
                break;
            case op_sub:
                fmt << " - ";
                res = a - b;
                break;
            case op_mult:
                fmt << " * ";
                res = a * b;
                break;
            case op_div:
                fmt << " / ";
                res = a / b;
                break;
        }
        fmt << "{2} = {3}";
        va << a.str() << b.str() << res.str();

        bs.vaprintf(fmt.c_str(), va);
        _logger->writeln(bs);
        _logger->writeln("precision(32) -> %s", res.fstr(32).c_str());
        _logger->writeln("c_str()       -> %s", res.str().c_str());
        _test_case.assert(res == expect, __FUNCTION__, "%s", bs.c_str());
    };

    // 0.1 + 0.2 = 0.3
    lambda(d1, d2, op_add, decimal_float(3, -1));
    // 0.1 + 1/3 = 1/10 + 1/3 = 3/30 + 10/30 = 13/30
    lambda(d1, r2, op_add, rational_float(13, 30));
    // 1/2 + 1/3 = 3/6 + 2/6 = 5/6
    lambda(r1, r2, op_add, rational_float(5, 6));

    // 0.1 - 0.2 = -0.1
    lambda(d1, d2, op_sub, decimal_float(-1, -1));
    // 0.1 - 1/3 = 1/10 - 1/3 = 3/30 - 10/30 = -7/30
    lambda(d1, r2, op_sub, rational_float(-7, 30));
    // 1/2 - 1/3 = 3/6 - 2/6 = 1/6
    lambda(r1, r2, op_sub, rational_float(1, 6));

    // 0.1 * 0.2 = 1/10 * 2/10 = 2/100
    lambda(d1, d2, op_mult, decimal_float(2, -2));
    // 0.1 * 1/3 = 1/10 * 1/3 = 1/30
    lambda(d1, r2, op_mult, rational_float(1, 30));
    // 1/2 * 1/3 = 1/6
    lambda(r1, r2, op_mult, rational_float(1, 6));

    // 0.1 / 0.2 = 1/10 / 2/10 = 1/10 * 10/2 = 1/2
    lambda(d1, d2, op_div, decimal_float(5, -1));
    // 0.1 / 1/3 = 1/10 / 1/3 = 1/10 * 3/1 = 3/10
    lambda(d1, r2, op_div, rational_float(3, 10));
    // 1/2 / 1/3 = 1/2 * 3/1 = 3/2
    lambda(r1, r2, op_div, rational_float(3, 2));

    auto lambda_arithmetic = [&](const std::string& a, const std::string& b, int op, const std::string& expect) -> void {
        valist va;
        basic_stream fmt;
        basic_stream bs;
        floating_point lhs;
        floating_point rhs;
        floating_point value;
        floating_point res;

        try {
            lhs = a;
            rhs = b;
            fmt << "{1}";
            switch (op) {
                case op_add:
                    fmt << " + ";
                    res = lhs + rhs;
                    break;
                case op_sub:
                    fmt << " - ";
                    res = lhs - rhs;
                    break;
                case op_mult:
                    fmt << " * ";
                    res = lhs * rhs;
                    break;
                case op_div:
                    fmt << " / ";
                    res = lhs / rhs;
                    break;
            }
            fmt << "{2} = {3} expect {4}";
            va << lhs.str() << rhs.str() << res.str() << expect;

            bs.vaprintf(fmt.c_str(), va);
            _logger->writeln(bs);
            try {
                value = expect;
                auto test = (res == value);
                _test_case.assert(test, __FUNCTION__, "%s", bs.c_str());
            } catch (...) {
                _test_case.assert(false, __FUNCTION__, "error %s", bs.c_str());
            }
        } catch (...) {
            _test_case.assert(false, __FUNCTION__, "error");
        }
    };

    lambda_arithmetic("1000000000000000.1", "1000000000000000.0", op_add, "2000000000000000.1");
    lambda_arithmetic("1000000000000000.1", "1000000000000000.0", op_sub, "0.1");
    lambda_arithmetic("1000000000000000.1", "1000000000000000.0", op_mult, "1.0000000000000001e+30");
    lambda_arithmetic("1000000000000000.1", "1000000000000000.0", op_div, "1.0000000000000001");
}

void testcase_floatingpoint() { test_floating_point(); }
