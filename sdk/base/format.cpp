/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdarg.h>

#include <hotplace/sdk/base/inline.hpp>
#include <hotplace/sdk/base/stl.hpp>
#include <ostream>

namespace hotplace {

std::string format(const char* fmt, ...) {
    va_list ap;
    const int size = 32;

    std::vector<char> buf(size);

    int ret = 0;
    int needed = size;

    while (true) {
        va_start(ap, fmt);
        ret = vsnprintf_inline(&buf[0], buf.size(), fmt, ap);
        va_end(ap);
        if ((ret < 0) || (ret >= needed)) {
            needed *= 2;
            buf.resize(needed + 1);
        } else {
            break;
        }
    }

    return std::string(&buf[0]);
}

#if __cplusplus > 199711L  // c++98
std::string format(const char* fmt, va_list ap) {
    const int size = 32;

    std::vector<char> buf(size);
    va_list vl;

    int ret = 0;
    int needed = size;

    while (true) {
        va_copy(vl, ap);  // c++99
        vsnprintf_inline(&buf[0], buf.size(), fmt, vl);
        va_end(vl);
        if ((ret < 0) || (ret >= needed)) {
            needed *= 2;
            buf.resize(needed + 1);
        } else {
            break;
        }
    }

    return std::string(&buf[0]);
}
#endif

}  // namespace hotplace
