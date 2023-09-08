/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO__
#define __HOTPLACE_SDK_IO__

#include <hotplace/sdk/base.hpp>

#include <hotplace/sdk/io/types.hpp>
#include <hotplace/sdk/io/basic/base16.hpp>
#include <hotplace/sdk/io/basic/base64.hpp>
#include <hotplace/sdk/io/basic/console_color.hpp>
#include <hotplace/sdk/io/basic/json.hpp>
#include <hotplace/sdk/io/basic/keyvalue.hpp>
#include <hotplace/sdk/io/basic/mlfq.hpp>
#include <hotplace/sdk/io/basic/obfuscate_string.hpp>
#include <hotplace/sdk/io/basic/zlib.hpp>
#include <hotplace/sdk/io/cbor/cbor.hpp>
#include <hotplace/sdk/io/stream/buffer_stream.hpp>
#include <hotplace/sdk/io/stream/bufferio.hpp>
#include <hotplace/sdk/io/stream/file_stream.hpp>
#include <hotplace/sdk/io/stream/stream.hpp>
#include <hotplace/sdk/io/stream/string.hpp>
#include <hotplace/sdk/io/string/string.hpp>
#include <hotplace/sdk/io/string/valist.hpp>
#include <hotplace/sdk/io/system/multiplexer.hpp>
#include <hotplace/sdk/io/system/sdk.hpp>
#include <hotplace/sdk/io/system/signalwait_threads.hpp>
#include <hotplace/sdk/io/system/thread.hpp>
#include <hotplace/sdk/io/system/types.hpp>
#if defined __linux__
#include <hotplace/sdk/io/system/linux/debug_trace.hpp>
#elif defined _WIN32 || defined _WIN64
#include <hotplace/sdk/io/system/windows/sdk.hpp>
#include <hotplace/sdk/io/system/windows/debug_trace.hpp>
#include <hotplace/sdk/io/system/windows/windows_registry.hpp>
#include <hotplace/sdk/io/system/windows/windows_version.hpp>
#endif
#include <hotplace/sdk/io/unittest/testcase.hpp>

#endif
