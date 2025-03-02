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

#ifndef __HOTPLACE_SDK_BASE_NOSTD_MINMAX__
#define __HOTPLACE_SDK_BASE_NOSTD_MINMAX__

#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/system/error.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

template <typename T>
class t_range {
   public:
    t_range() { reset(); }
    t_range(const t_range<T>& rhs) : _min(rhs._min), _max(rhs._max), _flag(rhs._flag) {}

    void test(const T& value) {
        _flag |= 0x1;
        if (value < _min) {
            _min = value;
        }
        if (value > _max) {
            _max = value;
        }
    }

    T getmin() const {
        if (0 == _flag) {
            T value = 0;
            int tsize = sizeof(T);
            memset(&value, 0x0, tsize);
            return value;
        } else {
            return _min;
        }
    }
    T getmax() const {
        if (0 == _flag) {
            T value = 0;
            int tsize = sizeof(T);
            memset(&value, 0xff, tsize);
            return value;
        } else {
            return _min;
        }
    }

    void reset() {
        int tsize = sizeof(T);
        memset(&_min, 0xff, tsize);  // max
        memset(&_max, 0x00, tsize);  // 0
        _flag = 0;
    }

   private:
    T _min;
    T _max;
    uint8 _flag;
};

}  // namespace hotplace

#endif
