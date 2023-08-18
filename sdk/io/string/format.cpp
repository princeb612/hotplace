/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base.hpp>
#include <stdarg.h>
#include <ostream>

namespace hotplace {
namespace io {

std::string format (const char* fmt, ...)
{
    va_list ap;
    const int size = 32;

    std::vector<char> buf (size);

    int ret = 0;
    int needed = size;

    va_start (ap, fmt);
    while (true) {
        ret = vsnprintf (&buf[0], buf.size (), fmt, ap); /* gcc only, msvc always return -1 */
        if ((ret < 0) || (ret >= needed)) {
            needed *= 2;
            buf.resize (needed + 1);
        } else {
            break;
        }
    }
    va_end (ap);

    return std::string (&buf[0]);
}

#if __cplusplus > 199711L    // c++98
std::string format (const char* fmt, va_list ap)
{
    const int size = 32;

    std::vector<char> buf (size);
    va_list vl;

    int ret = 0;
    int needed = size;

    va_copy (vl, ap); // c++99
    while (true) {
        ret = vsnprintf (&buf[0], buf.size (), fmt, vl);
        if ((ret < 0) || (ret >= needed)) {
            needed *= 2;
            buf.resize (needed + 1);
        } else {
            break;
        }
    }
    va_end (vl);

    return std::string (&buf[0]);
}
#endif

}
}
