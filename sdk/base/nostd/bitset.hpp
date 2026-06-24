/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   bitset.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_BITSET__
#define __HOTPLACE_SDK_BASE_NOSTD_BITSET__

#include <hotplace/sdk/base/basic/types.hpp>

namespace hotplace {

// std::bitset is not enough
class bitset {
   public:
    bitset(int low, int high);
    bitset(const bitset& other);
    bitset(bitset&& other);
    ~bitset();

    bitset& operator=(const bitset& other);
    bitset& operator=(bitset&& other);

    return_t add(int value);
    return_t subtract(int value);
    bool has(int value) const;
    bool has(const std::list<int>& values) const;
    binary_t get() const;
    uint8 unused_bit() const;

   protected:
    uint8 unused_bit(int value) const;

   private:
    int _low;
    int _high;
    binary_t _bitset;
};

}  // namespace hotplace

#endif
