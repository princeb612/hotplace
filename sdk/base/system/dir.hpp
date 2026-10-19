/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   dir.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_DIR__
#define __HOTPLACE_SDK_BASE_SYSTEM_DIR__

#include <sys/stat.h>
#include <sys/types.h>

#include <functional>
#include <hotplace/sdk/base/basic/types.hpp>
#if defined __linux__
#include <unistd.h>
#elif defined _WIN32 || defined _WIN64
#include <direct.h>
#include <io.h>
#endif

namespace hotplace {

inline bool makedir(const std::string& path) {
    if (path.empty()) {
        return false;
    }

    int ret = 0;
#if defined __linux__
    ret = mkdir(path.c_str(), 0755);
#elif defined _WIN32 || defined _WIN64
    ret = _mkdir(path.c_str());
#endif
    if (0 != ret) {
        struct stat info;
        if (stat(path.c_str(), &info) == 0 && (info.st_mode & S_IFDIR)) {
            return true;
        }
        return false;
    }
    return true;
}

inline bool makedirp(const std::string& path) {
    if (path.empty()) {
        return false;
    }

    std::string current_path;
    size_t len = path.length();

    for (size_t i = 0; i < len; ++i) {
        char c = path[i];

        if (c == '/' || c == '\\') {
            if (false == current_path.empty()) {
                if (false == (current_path.length() == 2 && current_path[1] == ':')) {
                    auto test = makedir(current_path);
                    if (0 == test) {
                        return false;
                    }
                }
            }
        }
        current_path += c;
    }

    if (!current_path.empty()) {
        return makedir(current_path);
    }

    return true;
}

}  // namespace hotplace

#endif
