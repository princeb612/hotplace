/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_STREAM_TYPES__
#define __HOTPLACE_SDK_BASE_STREAM_TYPES__

#include <list>
#include <sdk/base/basic/types.hpp>

namespace hotplace {

class ansi_string;
class basic_stream;
class bufferio;

#if defined _WIN32 || defined _WIN64
class wide_string;
#endif

}  // namespace hotplace

#endif
