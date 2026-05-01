/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   range.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_RANGE__
#define __HOTPLACE_SDK_BASE_NOSTD_RANGE__

#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/syntax.hpp>
#include <hotplace/sdk/base/system/error.hpp>
#include <hotplace/sdk/base/types.hpp>
#include <limits>

namespace hotplace {

template <typename T = size_t>
struct t_range_t {
    T begin;
    T end;
    t_range_t() : begin(0), end(0) {}
    t_range_t(size_t b, size_t e) : begin(std::min(b, e)), end(std::max(b, e)) {}
    bool operator<(const t_range_t& other) const {
        bool ret = false;
        if (begin < other.begin) {
            ret = true;
        } else if (begin == other.begin) {
            ret = (end < other.end);
        }
        return ret;
    }
    bool operator==(const t_range_t& other) const { return (begin == other.begin) && (end == other.end); }
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

typedef t_range_t<size_t> range_t;

/**
 * @sample
 *          t_sampling_range<int> sample;
 *          sample.sampling(1);   // getmin  1, getmax 1
 *          sample.sampling(-1);  // getmin -1, getmax 1
 *          sample.sampling(2);   // getmin -1, getmax 2
 *          sample.sampling(-2);  // getmin -2, getmax 1
 */
template <typename T>
class t_sampling_range {
   public:
    t_sampling_range() { reset(); }
    t_sampling_range(const t_sampling_range<T>& other) : _min(other._min), _max(other._max), _flag(other._flag) {}

    void sampling(const T& value) {
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

    t_sampling_range& operator=(const t_sampling_range<T>& other) {
        _min = other._min;
        _max = other._max;
        _flag = other._flag;
        return *this;
    }

   private:
    T _min;
    T _max;
    uint8 _flag;
};

}  // namespace hotplace

#endif
