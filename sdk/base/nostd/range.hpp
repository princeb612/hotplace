/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_RANGE__
#define __HOTPLACE_SDK_BASE_NOSTD_RANGE__

#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/system/error.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

struct range_t {
    size_t begin;
    size_t end;
    range_t() : begin(0), end(0) {}
    range_t(size_t b, size_t e) : begin(b), end(e) {}
    bool operator<(const range_t& rhs) const {
        bool ret = false;
        if (begin < rhs.begin) {
            ret = true;
        } else if (begin == rhs.begin) {
            ret = (end < rhs.end);
        }
        return ret;
    }
    bool operator==(const range_t& rhs) const { return (begin == rhs.begin) && (end == rhs.end); }
    size_t width() {
        size_t ret_value = 0;
        if (begin <= end) {
            ret_value = end - begin;
        } else {
            ret_value = begin - end;
        }
        return ret_value;
    }
};

/**
 * @brief   integer range
 * @sample
 *          t_integer_range<uint16> ui16;
 *          t_integer_range<int16> i16;
 *          t_integer_range<uint32> ui32;
 *          t_integer_range<int32> i32;
 *
 *          // (gdb) p/x ui16
 *          // $1 = {_imin = 0x0, _imax = 0xffff}
 *          // (gdb) p/x i16
 *          // $2 = {_imin = 0x8000, _imax = 0x7fff}
 *          // (gdb) p/x ui32
 *          // $3 = {_imin = 0x0, _imax = 0xffffffff}
 *          // (gdb) p/x i32
 *          // $4 = {_imin = 0x80000000, _imax = 0x7fffffff}
 *          // (gdb) p/x ui64
 *          // $5 = {_imin = 0x0, _imax = 0xffffffffffffffff}
 *          // (gdb) p/x i64
 *          // $6 = {_imin = 0x8000000000000000, _imax = 0x7fffffffffffffff}
 *          // (gdb) p/x ui128
 *          // $7 = {_imin = 0x0, _imax = 0xffffffffffffffffffffffffffffffff}
 *          // (gdb) p/x i128
 *          // $8 = {_imin = 0x80000000000000000000000000000000, _imax = 0x7fffffffffffffffffffffffffffffff}
 */
template <typename TYPE>
class t_integer_range {
   public:
    t_integer_range() : _imin(0), _imax(-1) {
        size_t bits = (sizeof(TYPE) << 3);
        bool is_signed = TYPE(-1) < TYPE(0);
        if (is_signed) {
            uint16 e = bits - 1;
            _imin = -(TYPE(1) << e);  // MSB set
            _imax = ~(_imin);         //
        }
    }

    TYPE getmin() { return _imin; }
    TYPE getmax() { return _imax; }

   private:
    TYPE _imin;
    TYPE _imax;
};

/**
 * @sample
 *          t_sampling_range<int> sample;
 *          sample.test(1);   // getmin  1, getmax 1
 *          sample.test(-1);  // getmin -1, getmax 1
 *          sample.test(2);   // getmin -1, getmax 2
 *          sample.test(-2);  // getmin -2, getmax 1
 */
template <typename T>
class t_sampling_range {
   public:
    t_sampling_range() { reset(); }
    t_sampling_range(const t_sampling_range<T>& rhs) : _min(rhs._min), _max(rhs._max), _flag(rhs._flag) {}

    void test(const T& value) {
        if (0 == _flag) {
            _min = value;
            _max = value;
        } else {
            if (value < _min) {
                _min = value;
            }
            if (value > _max) {
                _max = value;
            }
        }
        _flag |= 0x1;
    }

    T getmin() const {
        if (0 == _flag) {
            return T(0);
        } else {
            return _min;
        }
    }
    T getmax() const {
        if (0 == _flag) {
            return T(0);
        } else {
            return _max;
        }
    }

    void reset() {
        _min = T(0);
        _max = T(0);
        _flag = 0;
    }

   private:
    T _min;
    T _max;
    uint8 _flag;
};

}  // namespace hotplace

#endif
