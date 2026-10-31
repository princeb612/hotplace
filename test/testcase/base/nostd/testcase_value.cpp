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

// Revision 1122 - future-promise removed
void test_value() {
    _test_case.begin("value");

    t_value<int64> type1(1);
    auto value1 = type1.value();  // cached
    _test_case.assert(value1 == 1, __FUNCTION__, "get");

    auto routine = [](void* p) -> return_t {
        auto t = (t_value<int64>*)p;
        t->set_value(2);
        return errorcode_t::success;
    };

    t_value<int64> type2(0, "test");
    _test_case.assert(type2.is_named(), __FUNCTION__, "named");
    thread tr2(routine, &type2);  // set_value
    tr2.start();
    tr2.join();
    // if the thread does not operate, the value will wait indefinitely.
    auto value2 = type2.value();  // cached
    _test_case.assert(value2 == 2, __FUNCTION__, "get");
    int64 cache2 = type2;  // cached
    _test_case.assert(cache2 == 2, __FUNCTION__, "operator T()");

    t_value<int64> type3(1);
    type3.set_name("test");
    _test_case.assert(type3.get_name() == "test", __FUNCTION__, "get_name");
    _test_case.assert(type3.is_named(), __FUNCTION__, "named");
    thread tr3(routine, &type3);  // set_value
    tr3.start();
    tr3.join();
    auto value3 = type3.value();
    _test_case.assert(value3 == 2, __FUNCTION__, "value");
    value3 = type3.value();
    _test_case.assert(value3 == 2, __FUNCTION__, "return cached");
}

void test_range_value() {
    _test_case.begin("t_value in t_range_value");

    // test 1
    t_range_value<int64> range_val_literal;
    range_val_literal.type = range_type_t::value;
    range_val_literal.value = 20;  // Uses t_value's immediate value assignment

    _test_case.assert(range_val_literal.type == range_type_t::value, __FUNCTION__, "literal type check");
    _test_case.assert(range_val_literal.value.value() == 20, __FUNCTION__, "literal value check");

    // test 2
    t_range_value<int64> range_val_named;
    range_val_named.type = range_type_t::value;
    range_val_named.value.set_name("maxSize");

    _test_case.assert(range_val_named.type == range_type_t::value, __FUNCTION__, "named type check");
    _test_case.assert(range_val_named.value.is_named() == true, __FUNCTION__, "is named check");
    _test_case.assert(range_val_named.value.get_name() == "maxSize", __FUNCTION__, "parameter name check");

    // test 3
    range_val_named.value.set_value(1024);

    _test_case.assert(range_val_named.value.is_named() == true, __FUNCTION__, "still marked as named template ref");
    _test_case.assert(range_val_named.value.value() == 1024, __FUNCTION__, "resolved evaluation value check");

    // Test comparison operators implemented in t_value via t_range_value
    t_range_value<int64> range_val_compare;
    range_val_compare.type = range_type_t::value;
    range_val_compare.value = 500;

    _test_case.assert(range_val_compare.value < range_val_named.value, __FUNCTION__, "operator <");
}

void testcase_value() {
    test_value();
    test_range_value();
}
