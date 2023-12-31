/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <string.h>

#include <list>
#include <sdk/base/string/string.hpp>
#include <string>

namespace hotplace {

#if defined _MBCS || defined MBCS
void replace(std::string& source, std::string const& a, std::string const& b)
#elif defined _UNICODE || defined UNICODE
void replace(std::wstring& source, std::wstring const& a, std::wstring const& b)
#endif
{
    size_t i = source.find(a);

    while (std::string::npos != i) {
        source.replace(i, a.size(), b);
        i = source.find(a, i + b.size());
    }
}

}  // namespace hotplace
