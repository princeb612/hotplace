/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_TEMPLATE__
#define __HOTPLACE_SDK_BASE_TEMPLATE__

#include <functional>
#include <hotplace/sdk/base/charset.hpp>
#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/stream.hpp>
#include <hotplace/sdk/base/syntax.hpp>
#include <hotplace/sdk/base/types.hpp>

namespace hotplace {

template <typename RETURN_T, typename TYPE>
RETURN_T type_cast(TYPE param) {
    return static_cast<RETURN_T>(param);
}

template <typename T>
struct t_comparator_base {
    friend bool operator<(const T& lhs, const T& rhs) { return lhs < rhs; }
};

template <typename T>
struct t_type_comparator : t_comparator_base<T> {
    bool operator()(const T& lhs, const T& rhs) { return lhs.symbol < rhs.symbol; }
};

/**
 * @brief   atoi (int128)
 * @sample
 *          int128 i = 170141183460469231731687303715884105727; // warning
 *          i = t_atoi<int128>("170141183460469231731687303715884105727");
 *          i = t_atoi<int128>("-170141183460469231731687303715884105728");
 *
 *          basic_stream bs;
 *          bs.printf("%40I128i %032I128x", i, i);
 *
 *          //  170141183460469231731687303715884105727 7fffffffffffffffffffffffffffffff
 *          // -170141183460469231731687303715884105728 80000000000000000000000000000000
 */
template <typename TYPE>
TYPE t_atoi_n(const char* value, size_t size) {
    return_t ret = errorcode_t::success;
    TYPE res = 0;

    __try2 {
        if (nullptr == value) {
            __leave2;
        }

        size_t i = 0;
        int sign = 0;

        if (value[i] == '-') {
            ++i;
            sign = -1;
        }

        if (value[i] == '+') {
            ++i;
        }

        for (; i < size; ++i) {
            const char c = value[i];
            if (not std::isdigit(c)) {
                ret = errorcode_t::bad_data;
                break;
            }
            res *= 10;
            res += (c - '0');
        }

        if (errorcode_t::success != ret) {
            res = 0;
            __leave2;
        }

        if (sign < 0) {
            res = -res;
        }
    }
    __finally2 {}
    return res;
}

template <typename TYPE>
TYPE t_atoi(const std::string& value) {
    return t_atoi_n<TYPE>(value.c_str(), value.size());
}

/**
 * @return  unsigned integer value
 * @sa      t_atoi for signed/unsigned
 */
template <typename T>
T t_htoi(const char* hex) {
    T value = 0;
    const char* p = hex;
    char c = 0;
    int i = 0;
    while (c = *p++) {
        value <<= 4;
        if ('0' <= c && c <= '9') {
            i = c - '0';
        } else if ('A' <= c && c <= 'F') {
            i = c - 'A' + 10;
        } else if ('a' <= c && c <= 'f') {
            i = c - 'a' + 10;
        }
        value += i;
    }
    return value;
}

/**
 * @brief   byte capacity for signed integer
 * @sa      byte_capacity for unsigned integer
 * @example
 *          int byte_size = byte_capacity_signed<int128>(t_atoi<int128>("170141183460469231731687303715884105727"));
 *
 *                                               127 0000000000000000000000000000007f (1 bytes)
 *                                              -128 ffffffffffffffffffffffffffffff80 (1 bytes)
 *                                               128 00000000000000000000000000000080 (2 bytes)
 *                                              -129 ffffffffffffffffffffffffffffff7f (2 bytes)
 *                                             32767 00000000000000000000000000007fff (2 bytes)
 *                                            -32768 ffffffffffffffffffffffffffff8000 (2 bytes)
 *                                             32768 00000000000000000000000000008000 (3 bytes)
 *                                            -32769 ffffffffffffffffffffffffffff7fff (3 bytes)
 *                                           8388607 000000000000000000000000007fffff (3 bytes)
 *                                          -8388608 ffffffffffffffffffffffffff800000 (3 bytes)
 *                                        2147483647 0000000000000000000000007fffffff (4 bytes)
 *                                       -2147483648 ffffffffffffffffffffffff80000000 (4 bytes)
 *                                      549755813887 00000000000000000000007fffffffff (5 bytes)
 *                                     -549755813888 ffffffffffffffffffffff8000000000 (5 bytes)
 *                                   140737488355327 000000000000000000007fffffffffff (6 bytes)
 *                                  -140737488355328 ffffffffffffffffffff800000000000 (6 bytes)
 *                                 36028797018963967 0000000000000000007fffffffffffff (7 bytes)
 *                                -36028797018963968 ffffffffffffffffff80000000000000 (7 bytes)
 *                               9223372036854775807 00000000000000007fffffffffffffff (8 bytes)
 *                              -9223372036854775808 ffffffffffffffff8000000000000000 (8 bytes)
 *                            2361183241434822606847 000000000000007fffffffffffffffff (9 bytes)
 *                           -2361183241434822606848 ffffffffffffff800000000000000000 (9 bytes)
 *                          604462909807314587353087 0000000000007fffffffffffffffffff (10 bytes)
 *                         -604462909807314587353088 ffffffffffff80000000000000000000 (10 bytes)
 *                       154742504910672534362390527 00000000007fffffffffffffffffffff (11 bytes)
 *                      -154742504910672534362390528 ffffffffff8000000000000000000000 (11 bytes)
 *                     39614081257132168796771975167 000000007fffffffffffffffffffffff (12 bytes)
 *                    -39614081257132168796771975168 ffffffff800000000000000000000000 (12 bytes)
 *                  10141204801825835211973625643007 0000007fffffffffffffffffffffffff (13 bytes)
 *                 -10141204801825835211973625643008 ffffff80000000000000000000000000 (13 bytes)
 *                2596148429267413814265248164610047 00007fffffffffffffffffffffffffff (14 bytes)
 *               -2596148429267413814265248164610048 ffff8000000000000000000000000000 (14 bytes)
 *              664613997892457936451903530140172287 007fffffffffffffffffffffffffffff (15 bytes)
 *             -664613997892457936451903530140172288 ff800000000000000000000000000000 (15 bytes)
 *           170141183460469231731687303715884105727 7fffffffffffffffffffffffffffffff (16 bytes)
 *          -170141183460469231731687303715884105728 80000000000000000000000000000000 (16 bytes)
 */
template <typename signed_type>
int byte_capacity_signed(signed_type v) {
    int len = 1;
    if (v > 0) {
        v = ~v;  // 2's complement
    }
    while (v < -0x80) {
        v >>= 8;
        len++;
    }
    return len;
}

/**
 * @brief   util
 */
template <typename K, typename V>
class t_maphint {
   public:
    t_maphint(std::map<K, V>& source) : _source(source) {}

    return_t find(K const& key, V* value) {
        return_t ret = errorcode_t::success;

        if (value) {
            typename std::map<K, V>::iterator iter = _source.find(key);
            if (_source.end() == iter) {
                ret = errorcode_t::not_found;
            } else {
                *value = iter->second;
            }
        } else {
            ret = errorcode_t::invalid_parameter;
        }
        return ret;
    }

   private:
    std::map<K, V>& _source;
};

template <typename K, typename V>
class t_maphint_const {
   public:
    t_maphint_const(std::map<K, V> const& source) : _source(source) {}

    return_t find(K const& key, V* value) {
        return_t ret = errorcode_t::success;

        if (value) {
            typename std::map<K, V>::const_iterator iter = _source.find(key);
            if (_source.end() == iter) {
                ret = errorcode_t::not_found;
            } else {
                *value = iter->second;
            }
        } else {
            ret = errorcode_t::invalid_parameter;
        }
        return ret;
    }

   private:
    std::map<K, V> const& _source;
};

/**
 * @brief   delete
 * @example
 *          char* text = new char[10];
 *          delete [] text;
 *
 *          char* text = new char[10];
 *          t_promise_on_destroy<char*>(text, [](char* p) -> void { delete [] p; });
 *
 *          FILE* fp = fopen(...);
 *          t_promise_on_destroy<FILE*>(fp, [](FILE* file) -> void { fclose(file); });
 */
template <typename TYPE_PTR>
class t_promise_on_destroy {
   public:
    t_promise_on_destroy(TYPE_PTR object, std::function<void(TYPE_PTR)> func) : _object(object), _function(func) {}
    ~t_promise_on_destroy() {
        if (_object && _function) {
            _function(_object);
        }
    }

   private:
    TYPE_PTR _object;
    std::function<void(TYPE_PTR)> _function;
};

}  // namespace hotplace

#endif
