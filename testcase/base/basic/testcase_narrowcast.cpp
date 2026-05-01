/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_narrowcast.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

template <typename SOURCE>
struct t_my_narrow_cast_t {
    const SOURCE value;

    template <typename TYPE>
    operator TYPE() const {
        TYPE converted = static_cast<TYPE>(value);

        _logger->writeln([&](basic_stream& bs) -> void {
            valist va;  // handle unknown types
            va << value << converted;
            sprintf(&bs, "value {1} converted {2}", va);
        });

        /**
         * // compiler warning
         * if ((value > std::numeric_limits<TYPE>::max()) || (value < std::numeric_limits<TYPE>::min())) {
         *     throw exception(miscast_narrow);
         * }
         */

        if (static_cast<SOURCE>(converted) != value) {
            _logger->writeln("case.1");
            throw exception(miscast_narrow);
        }
        if (std::numeric_limits<SOURCE>::is_signed != std::numeric_limits<TYPE>::is_signed) {
            if ((value < 0) != (converted < 0)) {
                _logger->writeln("case.2");
                throw exception(miscast_narrow);
            }
        }
        return static_cast<TYPE>(value);
    }
};

template <typename TYPE>
constexpr t_my_narrow_cast_t<TYPE> t_my_narrow_cast(TYPE v) {
    return {v};
}

void check(const char* text, bool expect, std::function<void(void)> f) {
    int flag = 0;
    try {
        f();
    } catch (exception e) {
        flag = 1;
        _logger->writeln("errorcode 0x%08x : %s", e.get_errorcode(), e.get_error_message().c_str());
    }
    _test_case.assert(expect ? (flag == 1) : (flag == 0), __FUNCTION__, text);
}

void test_narrowcast() {
    _test_case.begin("narrow cast");
    return_t ret = errorcode_t::success;

    // signed to unsigned
    check("case.1", true, [&](void) -> void {
        int32 i32 = -1;
        uint16 ui16 = t_my_narrow_cast(i32);
    });

    // int16.max+1 to int16
    check("case.2", true, [&](void) -> void {
        int32 i32 = 32767 + 1;
        int16 i16 = t_my_narrow_cast(i32);
    });

    // uint32.max to int32
    check("case.3", true, [&](void) -> void {
        uint32 ui32 = 4294967295;
        int32 i32 = t_my_narrow_cast(ui32);
    });
}

void testcase_narrowcast() { test_narrowcast(); }
