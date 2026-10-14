/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_value.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/base/sample.hpp>

void test_value() {
    _test_case.begin("value - not exception-sensitive future-promise pattern");

    t_value<int64> type1(1);      // promise
    auto value1 = type1.value();  // cached
    _test_case.assert(value1 == 1, __FUNCTION__, "get");

    auto routine = [](void* p) -> return_t {
        auto t = (t_value<int64>*)p;
        t->set_value(2);
        return errorcode_t::success;
    };

    t_value<int64> type2(0, "test", true);  // deferred
    _test_case.assert(type2.deferred(), __FUNCTION__, "deferred");
    thread tr2(routine, &type2);  // set_value
    tr2.start();
    tr2.join();
    // if the thread does not operate, the value will wait indefinitely.
    auto value2 = type2.value();  // cached
    _test_case.assert(value2 == 2, __FUNCTION__, "get");
    int64 cache2 = type2;  // cached
    _test_case.assert(cache2 == 2, __FUNCTION__, "operator T()");

    t_value<int64> type3(1);  // promise
    type3.defer("test");      // defer
    _test_case.assert(type3.get_name() == "test", __FUNCTION__, "get_name");
    _test_case.assert(type3.deferred(), __FUNCTION__, "deferred");
    thread tr3(routine, &type3);  // set_value
    tr3.start();
    tr3.join();
    auto value3 = type3.value();  // future is valid
    _test_case.assert(value3 == 2, __FUNCTION__, "defer and value");
    value3 = type3.value();  // cached
    _test_case.assert(value3 == 2, __FUNCTION__, "return cached");
}

void test_range_value() {
    _test_case.begin("t_value in t_range_value");

    // 1. Literal range value test (e.g., fixed value 20)
    t_range_value<int64> range_val_literal;
    range_val_literal.type = range_type_t::value;
    range_val_literal.value = 20;  // Uses t_value's immediate value assignment

    _test_case.assert(range_val_literal.type == range_type_t::value, __FUNCTION__, "literal type check");
    _test_case.assert(range_val_literal.value.value() == 20, __FUNCTION__, "literal value check");
    _test_case.assert(range_val_literal.value.deferred() == false, __FUNCTION__, "literal is not deferred");

    // 2. Deferred / Parameterized range value test (using defer interface)
    t_range_value<int64> range_val_deferred;
    range_val_deferred.type = range_type_t::value;
    range_val_deferred.value.defer("maxSize");  // Explicitly invoke the updated defer method

    _test_case.assert(range_val_deferred.type == range_type_t::value, __FUNCTION__, "deferred type check");
    _test_case.assert(range_val_deferred.value.deferred() == true, __FUNCTION__, "is deferred check");
    _test_case.assert(range_val_deferred.value.get_name() == "maxSize", __FUNCTION__, "parameter name check");

    // 3. Evaluation-time resolution test (Specialization simulation)
    // Simulate specialization by setting value via set_value()
    range_val_deferred.value.set_value(1024);

    _test_case.assert(range_val_deferred.value.deferred() == true, __FUNCTION__, "still marked as deferred template ref");
    _test_case.assert(range_val_deferred.value.value() == 1024, __FUNCTION__, "resolved evaluation value check");

    // Test comparison operators implemented in t_value via t_range_value
    t_range_value<int64> range_val_compare;
    range_val_compare.type = range_type_t::value;
    range_val_compare.value = 500;

    _test_case.assert(range_val_compare.value < range_val_deferred.value, __FUNCTION__, "operator <");
}

void testcase_value() {
    test_value();
    test_range_value();
}
