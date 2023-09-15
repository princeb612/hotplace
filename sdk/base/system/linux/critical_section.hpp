/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_LINUX_CRITICALSECTION__
#define __HOTPLACE_SDK_BASE_SYSTEM_LINUX_CRITICALSECTION__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <pthread.h>

namespace hotplace {

class critical_section : public critical_section_t
{
public:
    /**
     * @brief constructor
     */
    critical_section ()
    {
        startup ();
    }

    /**
     * @brief destructor
     */
    virtual ~critical_section ()
    {
        cleanup ();
    }

    /**
     * @brief enter critical section
     */
    virtual void enter ()
    {
        pthread_mutex_lock (&_mutex_handle);
    }

    /**
     * @brief leave critical section
     */
    virtual void leave ()
    {
        pthread_mutex_unlock (&_mutex_handle);
    }

private:
    /**
     * @brief startup
     */
    void startup ()
    {
        pthread_mutexattr_init (&_mutex_attributes);
        pthread_mutexattr_settype (&_mutex_attributes, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init (&_mutex_handle, &_mutex_attributes);
    }
    /**
     * @brief cleanup
     */
    void cleanup ()
    {
        pthread_mutex_destroy (&_mutex_handle);
    }

    pthread_mutex_t _mutex_handle;
    pthread_mutexattr_t _mutex_attributes;
};

}  // namespace

#endif
