/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   redirection.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_LINUX_REDIRECTION__
#define __HOTPLACE_SDK_BASE_SYSTEM_LINUX_REDIRECTION__

#include <spawn.h>

#include <hotplace/sdk/base/system/redirection.hpp>

namespace hotplace {

class HOTPLACE_BASE_API redirection : public redirection_t {
   public:
    redirection();
    virtual ~redirection();

    bool initialize(posix_spawn_file_actions_t* file_actions);
    void event_spawned();
    virtual size_t read_stdout(void* buffer, size_t size);
    virtual size_t write_stdin(const void* data, size_t size);
    virtual void close();

    int get_stdin_handle() const;
    int get_stdout_handle() const;

   private:
    int _stdin_pipe{-1};
    int _stdout_pipe{-1};
    int _stdin_child_fd{-1};
    int _stdout_child_fd{-1};
};

}  // namespace hotplace

#endif
