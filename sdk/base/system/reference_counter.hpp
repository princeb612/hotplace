/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_REFERENCECOUNTER__
#define __HOTPLACE_SDK_BASE_SYSTEM_REFERENCECOUNTER__

#include <sdk/base/system/atomic.hpp>

namespace hotplace {

/**
 * @brief reference counter
 * @remakrs
 *      concept
 *      class sample
 *      {
 *      public:
 *          sample() { _refcount.addref(); }
 *          ~sample() {}
 *
 *          int do_something() {}
 *          int release() { if (0 == _refcount.delref()) { delete this; } }
 *      private:
 *          reference_counter _refcount;
 *      };
 *
 *      sample_ptr = new sample(); // ++refcount
 *      sample_ptr->addref (); // ++refcount
 *      sample_ptr->do_something();
 *      sample_ptr->release(); // --refcount
 *      sample_ptr->do_something();
 *      sample_ptr->release(); // --refcount
 */
class reference_counter {
   public:
    /**
     * @brief constructor
     */
    reference_counter() : _count(0) {
        // do nothing
    }

    /**
     * @brief increase reference counter (V)
     */
    int addref() {
        atomic_increment(&_count);
        return _count;
    }

    /**
     * @brief decrease reference counter (P)
     */
    int delref() {
        atomic_decrement(&_count);
        return _count;
    }

    /**
     * @brief return reference counter
     */
    int getref() { return _count; }

   private:
    int _count;
};

}  // namespace hotplace

#endif
