/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   process.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_PROCESS__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_PROCESS__

#include <hotplace/sdk/base/system/process.hpp>
#include <hotplace/sdk/base/system/redirection.hpp>

namespace hotplace {

class HOTPLACE_BASE_API process : public process_t {
   public:
    process();
    virtual ~process();

    virtual bool spawn(const execparam& param);
    virtual int wait();
    virtual void terminate();
    virtual bool isrunning();
    virtual redirection_t* get_redirection() const;

   private:
    PROCESS_INFORMATION _pi;
    HANDLE _handle;
    redirection_t* _redirection{nullptr};
};

}  // namespace hotplace

#endif
