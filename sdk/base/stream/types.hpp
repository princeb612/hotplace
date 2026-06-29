/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_STREAM_TYPES__
#define __HOTPLACE_SDK_BASE_STREAM_TYPES__

#include <hotplace/sdk/base/basic/types.hpp>
#include <list>

namespace hotplace {

struct bufferio_context_t;

class ansi_string;
class basic_stream;
class bufferio;
#if defined _WIN32 || defined _WIN64
class wide_string;
#endif

#if defined _WIN32 || defined _WIN64

return_t A2W(wide_string& target, const char* source, uint32 codepage = 0);
return_t W2A(ansi_string& target, const wchar_t* source, uint32 codepage = 0);
return_t A2W(stream_t* stream, const char* source, uint32 codepage = 0);
return_t W2A(stream_t* stream, const wchar_t* source, uint32 codepage = 0);

#endif

}  // namespace hotplace

#endif
