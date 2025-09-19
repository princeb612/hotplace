/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_CRITICALSECTION__
#define __HOTPLACE_SDK_BASE_SYSTEM_CRITICALSECTION__

#include <hotplace/sdk/base/charset.hpp>
#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/syntax.hpp>
#include <hotplace/sdk/base/types.hpp>

namespace hotplace {

class critical_section_t {
   public:
    virtual ~critical_section_t() {}
    virtual void enter() = 0;
    virtual void leave() = 0;
};

}  // namespace hotplace

#if defined _WIN32 || defined _WIN64
#include <hotplace/sdk/base/system/windows/critical_section.hpp>
#elif defined __linux__
#include <hotplace/sdk/base/system/linux/critical_section.hpp>
#endif

namespace hotplace {

class critical_section_guard {
   public:
    critical_section_guard(critical_section& cs) {
        cs.enter();
        _cs = &cs;
    }
    ~critical_section_guard() { _cs->leave(); }

   private:
    critical_section* _cs;
};

}  // namespace hotplace

#endif
