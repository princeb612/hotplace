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

namespace hotplace {

class critical_section_t {
   public:
    virtual ~critical_section_t() {}
    virtual void enter() = 0;
    virtual void leave() = 0;
};

}  // namespace hotplace

#if defined _WIN32 || defined _WIN64
#include <sdk/base/system/windows/critical_section.hpp>
#elif defined __linux__
#include <sdk/base/system/linux/critical_section.hpp>
#endif

namespace hotplace {

class enter_critical_section {
   public:
    enter_critical_section(critical_section& cs) {
        cs.enter();
        _cs = &cs;
    }
    ~enter_critical_section() { _cs->leave(); }

   private:
    critical_section* _cs;
};

}  // namespace hotplace

#endif
