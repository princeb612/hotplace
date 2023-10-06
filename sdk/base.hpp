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

#include <hotplace/sdk/base/types.hpp>
#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/c++14.hpp>
#include <hotplace/sdk/base/charset.hpp>
#include <hotplace/sdk/base/callback.hpp>
#include <hotplace/sdk/base/inline.hpp>
#include <hotplace/sdk/base/stl.hpp>
#include <hotplace/sdk/base/syntax.hpp>
#include <hotplace/sdk/base/stream.hpp>

#include <hotplace/sdk/base/basic/base16.hpp>
#include <hotplace/sdk/base/basic/base64.hpp>
#include <hotplace/sdk/base/basic/bufferio.hpp>
#include <hotplace/sdk/base/basic/cmdline.hpp>
#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/basic/ieee754.hpp>
#include <hotplace/sdk/base/basic/printf.hpp>
#include <hotplace/sdk/base/basic/valist.hpp>
#include <hotplace/sdk/base/basic/variant.hpp>

#include <hotplace/sdk/base/system/atomic.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/base/system/datetime.hpp>
#include <hotplace/sdk/base/system/endian.hpp>
#include <hotplace/sdk/base/system/reference_counter.hpp>
#include <hotplace/sdk/base/system/semaphore.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/base/system/signalwait_threads.hpp>
#include <hotplace/sdk/base/system/thread.hpp>

#if defined _WIN32 || defined _WIN64
#include <hotplace/sdk/base/system/windows/sdk.hpp>
#include <hotplace/sdk/base/system/windows/windows_version.hpp>
#endif

#endif
