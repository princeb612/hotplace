/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE__
#define __HOTPLACE_SDK_BASE__

/* top-most */
#include <sdk/base/c++14.hpp>
#include <sdk/base/callback.hpp>
#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/inline.hpp>
#include <sdk/base/stl.hpp>
#include <sdk/base/stream.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>

/* basic */
//#include <sdk/base/basic/avl.hpp>
#include <sdk/base/basic/base16.hpp>
#include <sdk/base/basic/base64.hpp>
#include <sdk/base/basic/cmdline.hpp>
#include <sdk/base/basic/console_color.hpp>
#include <sdk/base/basic/constexpr_obfuscate.hpp>
#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/basic/ieee754.hpp>
#include <sdk/base/basic/obfuscate_string.hpp>
#include <sdk/base/basic/valist.hpp>
#include <sdk/base/basic/variant.hpp>

/* stream */
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/stream/bufferio.hpp>
#include <sdk/base/stream/printf.hpp>

/* string */
#include <sdk/base/string/string.hpp>

/* system */
#include <sdk/base/system/atomic.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/datetime.hpp>
#if defined __linux__
#include <sdk/base/system/linux/debug_trace.hpp>
#elif defined _WIN32 || defined _WIN64
#include <sdk/base/system/windows/debug_trace.hpp>
#endif
#include <sdk/base/system/endian.hpp>
#include <sdk/base/system/reference_counter.hpp>
#include <sdk/base/system/semaphore.hpp>
#include <sdk/base/system/shared_instance.hpp>
#include <sdk/base/system/signalwait_threads.hpp>
#include <sdk/base/system/thread.hpp>
#include <sdk/base/system/trace.hpp>
#include <sdk/base/system/types.hpp>
#if defined _WIN32 || defined _WIN64
#include <sdk/base/system/windows/sdk.hpp>
#include <sdk/base/system/windows/windows_version.hpp>
#endif

/* unittest */
#include <sdk/base/unittest/testcase.hpp>

#endif
