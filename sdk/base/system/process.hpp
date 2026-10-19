/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   process.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_PROCESS__
#define __HOTPLACE_SDK_BASE_SYSTEM_PROCESS__

#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/string/string.hpp>
#include <hotplace/sdk/base/system/redirection.hpp>
#include <hotplace/sdk/base/system/types.hpp>

namespace hotplace {

struct execparam {
    std::string executable;
    std::vector<std::string> arguments;
    std::string workdir;
    bool io_redirection{false};

    void clear() {
        executable.clear();
        arguments.clear();
        workdir.clear();
    }
    execparam& add(const std::string& arg) {
        arguments.push_back(arg);
        return *this;
    }
    execparam& add(int value) {
        arguments.push_back(format("%i", value));
        return *this;
    }
};

class process_t {
   public:
    virtual ~process_t() {}
    virtual bool spawn(const execparam& param) = 0;
    virtual int wait() = 0;
    virtual void terminate() = 0;
    virtual bool isrunning() = 0;
    virtual redirection_t* get_redirection() const = 0;
};

}  // namespace hotplace

#if defined _WIN32 || defined _WIN64
#include <hotplace/sdk/base/system/windows/process.hpp>
#elif defined __linux__
#include <hotplace/sdk/base/system/linux/process.hpp>
#endif

#endif
