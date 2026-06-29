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
class t_set_t {
   public:
    virtual ~t_set_t() = default;
    virtual void insert(T value) = 0;
    virtual void insert_range(T start, T end) = 0;
    virtual void erase(T value) = 0;
    virtual void erase_range(T start, T end) = 0;
    virtual bool contains(T value) = 0;
    virtual void reset() = 0;
};

}  // namespace hotplace

#endif
