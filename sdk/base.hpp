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
#include <sdk/base/stream.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/template.hpp>
#include <sdk/base/trace.hpp>
#include <sdk/base/types.hpp>

/* basic */
#include <sdk/base/basic/base16.hpp>
#include <sdk/base/basic/base64.hpp>
#include <sdk/base/basic/binaries.hpp>
#include <sdk/base/basic/binary.hpp>
#include <sdk/base/basic/cmdline.hpp>
#include <sdk/base/basic/console_color.hpp>
#include <sdk/base/basic/constexpr_obfuscate.hpp>
#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/basic/huffman_coding.hpp>
#include <sdk/base/basic/ieee754.hpp>
#include <sdk/base/basic/keyvalue.hpp>
#include <sdk/base/basic/obfuscate_string.hpp>
#include <sdk/base/basic/types.hpp>
#include <sdk/base/basic/valist.hpp>
#include <sdk/base/basic/variant.hpp>

/* graph */
#include <sdk/base/graph/graph.hpp>

/* nostd */
#include <sdk/base/nostd/exception.hpp>
#include <sdk/base/nostd/integer.hpp>
#include <sdk/base/nostd/list.hpp>
#include <sdk/base/nostd/ovl.hpp>
#include <sdk/base/nostd/pq.hpp>
#include <sdk/base/nostd/range.hpp>
#include <sdk/base/nostd/template.hpp>
#include <sdk/base/nostd/tree.hpp>
#include <sdk/base/nostd/vector.hpp>

/* pattern */
#include <sdk/base/pattern/aho_corasick.hpp>
#include <sdk/base/pattern/aho_corasick_wildcard.hpp>
#include <sdk/base/pattern/kmp.hpp>
#include <sdk/base/pattern/pattern.hpp>
#include <sdk/base/pattern/suffixtree.hpp>
#include <sdk/base/pattern/trie.hpp>
#include <sdk/base/pattern/ukkonen.hpp>
#include <sdk/base/pattern/wildcard.hpp>

/* stream */
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/stream/bufferio.hpp>
#include <sdk/base/stream/fragmentation.hpp>
#include <sdk/base/stream/printf.hpp>
#include <sdk/base/stream/segmentation.hpp>
#include <sdk/base/stream/split.hpp>
#include <sdk/base/stream/tstring.hpp>
#include <sdk/base/stream/types.hpp>

/* string */
#include <sdk/base/string/string.hpp>

/* system */
#include <sdk/base/system/atomic.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/datetime.hpp>
#include <sdk/base/system/endian.hpp>
#include <sdk/base/system/error.hpp>
#if defined __linux__
#include <sdk/base/system/linux/debug_trace.hpp>
#elif defined _WIN32 || defined _WIN64
#include <sdk/base/system/windows/debug_trace.hpp>
#endif
#include <sdk/base/system/reference_counter.hpp>
#include <sdk/base/system/semaphore.hpp>
#include <sdk/base/system/shared_instance.hpp>
#include <sdk/base/system/signalwait_threads.hpp>
#include <sdk/base/system/thread.hpp>
#include <sdk/base/system/types.hpp>
#if defined _WIN32 || defined _WIN64
#include <sdk/base/system/windows/sdk.hpp>
#include <sdk/base/system/windows/windows_version.hpp>
#endif

/* unittest */
#include <sdk/base/unittest/logger.hpp>
#include <sdk/base/unittest/testcase.hpp>
#include <sdk/base/unittest/trace.hpp>

#endif
