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

#include <hotplace/sdk/base/system/critical_section.hpp>

namespace hotplace {

class critical_section : public critical_section_interface
{
public:
    /**
     * @brief constructor
     */
    critical_section ()
    {
        initialize ();
    }

    /**
     * @brief destructor
     */
    virtual ~critical_section ()
    {
        finalize ();
    }

    /**
     * @brief enter critical section
     */
    virtual void enter ()
    {
        ::EnterCriticalSection (&m_cs);
    }

    /**
     * @brief leave critical section
     */
    virtual void leave ()
    {
        ::LeaveCriticalSection (&m_cs);
    }

private:
    /**
     * @brief initialize
     */
    void initialize ()
    {
        ::InitializeCriticalSectionAndSpinCount (&m_cs, 2048);
    }
    /**
     * @brief finalize
     */
    void finalize ()
    {
        ::DeleteCriticalSection (&m_cs);
    }

    CRITICAL_SECTION m_cs;
};

}  // namespace

#endif
