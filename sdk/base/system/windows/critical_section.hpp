/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_CRITICALSECTION__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_CRITICALSECTION__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/windows/types.hpp>

namespace hotplace {

class critical_section : public critical_section_t {
   public:
    /**
     * @brief constructor
     */
    critical_section() { startup(); }

    /**
     * @brief destructor
     */
    virtual ~critical_section() { cleanup(); }

    /**
     * @brief enter critical section
     */
    virtual void enter() { ::EnterCriticalSection(&m_cs); }

    /**
     * @brief leave critical section
     */
    virtual void leave() { ::LeaveCriticalSection(&m_cs); }

   private:
    /**
     * @brief startup
     */
    void startup() { ::InitializeCriticalSectionAndSpinCount(&m_cs, 2048); }
    /**
     * @brief cleanup
     */
    void cleanup() { ::DeleteCriticalSection(&m_cs); }

    CRITICAL_SECTION m_cs;
};

}  // namespace hotplace

#endif
