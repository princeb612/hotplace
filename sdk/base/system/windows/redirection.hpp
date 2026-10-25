/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   redirection.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_REDIRECTION__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_REDIRECTION__

#include <hotplace/sdk/base/system/redirection.hpp>

namespace hotplace {

class HOTPLACE_BASE_API redirection : public redirection_t {
   public:
    redirection();
    virtual ~redirection();

    bool initialize(SECURITY_ATTRIBUTES* sa);
    void event_spawned();
    virtual size_t read_stdout(void* buffer, size_t size);
    virtual size_t write_stdin(const void* data, size_t size);
    virtual void close();

    // parent-side handles (used by parent for read/write)
    HANDLE get_stdin_write_handle() const;
    HANDLE get_stdout_read_handle() const;

    // child-side handles (passed to child process STARTUPINFO)
    HANDLE get_stdin_read_handle() const;
    HANDLE get_stdout_write_handle() const;

   private:
    HANDLE _handle_stdin_read{nullptr};
    HANDLE _handle_stdin_write{nullptr};
    HANDLE _handle_stdout_read{nullptr};
    HANDLE _handle_stdout_write{nullptr};
};

}  // namespace hotplace

#endif
