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
#include <hotplace/sdk/base/c++14.hpp>
#include <hotplace/sdk/base/callback.hpp>
#include <hotplace/sdk/base/charset.hpp>
#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/inline.hpp>
#include <hotplace/sdk/base/stream.hpp>
#include <hotplace/sdk/base/syntax.hpp>
#include <hotplace/sdk/base/template.hpp>
#include <hotplace/sdk/base/trace.hpp>
#include <hotplace/sdk/base/types.hpp>

/* basic */
#include <hotplace/sdk/base/basic/base16.hpp>
#include <hotplace/sdk/base/basic/base64.hpp>
#include <hotplace/sdk/base/basic/binaries.hpp>
#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/basic/cmdline.hpp>
#include <hotplace/sdk/base/basic/constexpr_obfuscate.hpp>
#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/basic/huffman_coding.hpp>
#include <hotplace/sdk/base/basic/ieee754.hpp>
#include <hotplace/sdk/base/basic/keyvalue.hpp>
#include <hotplace/sdk/base/basic/obfuscate_string.hpp>
#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/basic/valist.hpp>
#include <hotplace/sdk/base/basic/variant.hpp>

/* graph */
#include <hotplace/sdk/base/graph/graph.hpp>

/* nostd */
#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/nostd/integer.hpp>
#include <hotplace/sdk/base/nostd/list.hpp>
#include <hotplace/sdk/base/nostd/ovl.hpp>
#include <hotplace/sdk/base/nostd/pq.hpp>
#include <hotplace/sdk/base/nostd/range.hpp>
#include <hotplace/sdk/base/nostd/template.hpp>
#include <hotplace/sdk/base/nostd/tree.hpp>
#include <hotplace/sdk/base/nostd/vector.hpp>

/* pattern */
#include <hotplace/sdk/base/pattern/aho_corasick.hpp>
#include <hotplace/sdk/base/pattern/aho_corasick_wildcard.hpp>
#include <hotplace/sdk/base/pattern/kmp.hpp>
#include <hotplace/sdk/base/pattern/pattern.hpp>
#include <hotplace/sdk/base/pattern/suffixtree.hpp>
#include <hotplace/sdk/base/pattern/trie.hpp>
#include <hotplace/sdk/base/pattern/ukkonen.hpp>
#include <hotplace/sdk/base/pattern/wildcard.hpp>

/* stream */
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/stream/bufferio.hpp>
#include <hotplace/sdk/base/stream/printf.hpp>
#include <hotplace/sdk/base/stream/split.hpp>
#include <hotplace/sdk/base/stream/tstring.hpp>
#include <hotplace/sdk/base/stream/types.hpp>

/* string */
#include <hotplace/sdk/base/string/string.hpp>

/* system */
#include <hotplace/sdk/base/system/atomic.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/base/system/datetime.hpp>
#include <hotplace/sdk/base/system/endian.hpp>
#include <hotplace/sdk/base/system/error.hpp>
#if defined __linux__
#include <hotplace/sdk/base/system/linux/debug_trace.hpp>
#elif defined _WIN32 || defined _WIN64
#include <hotplace/sdk/base/system/windows/debug_trace.hpp>
#endif
#include <hotplace/sdk/base/system/reference_counter.hpp>
#include <hotplace/sdk/base/system/semaphore.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/base/system/signalwait_threads.hpp>
#include <hotplace/sdk/base/system/thread.hpp>
#include <hotplace/sdk/base/system/types.hpp>
#include <hotplace/sdk/base/system/uint.hpp>
#if defined _WIN32 || defined _WIN64
#include <hotplace/sdk/base/system/windows/sdk.hpp>
#include <hotplace/sdk/base/system/windows/windows_version.hpp>
#endif

/* unittest */
#include <hotplace/sdk/base/unittest/console_color.hpp>
#include <hotplace/sdk/base/unittest/logger.hpp>
#include <hotplace/sdk/base/unittest/testcase.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>

#endif
