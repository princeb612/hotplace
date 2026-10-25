/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   process.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_LINUX_PROCESS__
#define __HOTPLACE_SDK_BASE_SYSTEM_LINUX_PROCESS__

#include <hotplace/sdk/base/system/process.hpp>
#include <hotplace/sdk/base/system/redirection.hpp>

namespace hotplace {

/**
 * https://man7.org/linux/man-pages/man3/posix_spawn.3.html
 */
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
    pid_t _pid{-1};
    int _exit_code{-1};
    bool _is_running{false};
    redirection_t* _redirection{nullptr};
};

}  // namespace hotplace

#endif
