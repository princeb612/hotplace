/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_TYPES__
#define __HOTPLACE_SDK_BASE_NOSTD_TYPES__

#include <hotplace/sdk/base/basic/types.hpp>

namespace hotplace {

template <typename T>
class t_set_base_t {
   public:
    virtual ~t_set_base_t() = default;
    virtual void reset() = 0;
    virtual void insert(const T& value) = 0;
    virtual void erase(const T& value) = 0;
    virtual bool contains(const T& value) = 0;
};

template <typename T>
class t_set_arithmetic_t {
   public:
    virtual ~t_set_arithmetic_t() = default;
    virtual void insert_range(const T& start, const T& end) = 0;
    virtual void erase_range(const T& start, const T& end) = 0;
};

}  // namespace hotplace

#endif
