/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 *
 * sketch 1 applied
 *
 * sketch 1 (2 phases)
 *      // calc bumper (the size of the fragment header)
 *      // then fragmentation (both pos and len as in parameter)
 *      return_t consume(uint32 type, size_t bumper, std::function<return_t(const byte_t*, size_t, size_t, size_t)> func);
 *
 * sketch 2 (1 phase)
 *      // calc bumper (the size of the fragment header) while fragmentation
 *      // bumper as out parameter in consume method
 */

#ifndef __HOTPLACE_SDK_BASE_STREAM_FRAGMENTATION__
#define __HOTPLACE_SDK_BASE_STREAM_FRAGMENTATION__

#include <sdk/base/stream/segmentation.hpp>

namespace hotplace {

/**
 * @brief fragmentation
 */
class fragmentation {
   public:
    fragmentation();

    return_t consume(uint32 type, size_t bumper, std::function<return_t(const byte_t*, size_t, size_t, size_t)> func);

    return_t set(segmentation* segment, size_t concat = 0);
    segmentation* get_segment();
    size_t get_fragment_size();

    return_t use(size_t size);
    size_t used();
    size_t available();

   protected:
   private:
    segmentation* _segment;
    size_t _fragment_size;
    size_t _used;
};

}  // namespace hotplace

#endif
