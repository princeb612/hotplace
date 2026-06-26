/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   base.hpp
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
#include <hotplace/sdk/base/trace.hpp>
#include <hotplace/sdk/base/types.hpp>

/* basic */
#include <hotplace/sdk/base/basic/cmdline.hpp>
#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/basic/valist.hpp>
#include <hotplace/sdk/base/basic/variant.hpp>

/* encoding */
#include <hotplace/sdk/base/encoding/base16.hpp>
#include <hotplace/sdk/base/encoding/base64.hpp>
#include <hotplace/sdk/base/encoding/decoder_stream.hpp>
#include <hotplace/sdk/base/encoding/encoder_stream.hpp>
#include <hotplace/sdk/base/encoding/http_huffman_codes.hpp>
#include <hotplace/sdk/base/encoding/http_huffman_coding.hpp>
#include <hotplace/sdk/base/encoding/huffman_coding.hpp>

/* graph */
#include <hotplace/sdk/base/graph/graph.hpp>

/* nostd */
#include <hotplace/sdk/base/nostd/atoi.hpp>
#include <hotplace/sdk/base/nostd/avltree.hpp>
#include <hotplace/sdk/base/nostd/binaries.hpp>
#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/base/nostd/bit_set.hpp>
#include <hotplace/sdk/base/nostd/btree.hpp>
#include <hotplace/sdk/base/nostd/capacity.hpp>
#include <hotplace/sdk/base/nostd/cast.hpp>
#include <hotplace/sdk/base/nostd/enumclass.hpp>
#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/nostd/keyvalue.hpp>
#include <hotplace/sdk/base/nostd/list.hpp>
#include <hotplace/sdk/base/nostd/memory.hpp>
#include <hotplace/sdk/base/nostd/point_set.hpp>
#include <hotplace/sdk/base/nostd/pq.hpp>
#include <hotplace/sdk/base/nostd/range.hpp>
#include <hotplace/sdk/base/nostd/range_set.hpp>
#include <hotplace/sdk/base/nostd/traits.hpp>
#include <hotplace/sdk/base/nostd/traits_encoder.hpp>
#include <hotplace/sdk/base/nostd/traits_printf.hpp>
#include <hotplace/sdk/base/nostd/utility.hpp>
#include <hotplace/sdk/base/nostd/vector.hpp>

/* pattern */
#include <hotplace/sdk/base/pattern/aho_corasick.hpp>
#include <hotplace/sdk/base/pattern/aho_corasick_wildcard.hpp>
#include <hotplace/sdk/base/pattern/kmp.hpp>
#include <hotplace/sdk/base/pattern/pattern.hpp>
#include <hotplace/sdk/base/pattern/regex.hpp>
#include <hotplace/sdk/base/pattern/suffixtree.hpp>
#include <hotplace/sdk/base/pattern/trie.hpp>
#include <hotplace/sdk/base/pattern/ukkonen.hpp>
#include <hotplace/sdk/base/pattern/wildcard.hpp>

/* stream */
#include <hotplace/sdk/base/stream/ansi_string.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/stream/bufferio.hpp>
#include <hotplace/sdk/base/stream/printf.hpp>
#include <hotplace/sdk/base/stream/split.hpp>
#include <hotplace/sdk/base/stream/splitter.hpp>
#include <hotplace/sdk/base/stream/sprintf.hpp>
#include <hotplace/sdk/base/stream/stream.hpp>
#include <hotplace/sdk/base/stream/stream_policy.hpp>
#include <hotplace/sdk/base/stream/types.hpp>
#include <hotplace/sdk/base/stream/unicode/wide_string.hpp>
#include <hotplace/sdk/base/stream/vtprintf.hpp>

/* string */
#include <hotplace/sdk/base/string/constexpr_obfuscate.hpp>
#include <hotplace/sdk/base/string/obfuscate_string.hpp>
#include <hotplace/sdk/base/string/string.hpp>
#include <hotplace/sdk/base/string/types.hpp>

/* system */
#include <hotplace/sdk/base/system/atomic.hpp>
#include <hotplace/sdk/base/system/bignumber.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/base/system/datetime.hpp>
#include <hotplace/sdk/base/system/endian.hpp>
#include <hotplace/sdk/base/system/error.hpp>
#include <hotplace/sdk/base/system/floating_point.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#if defined __linux__
#include <hotplace/sdk/base/system/linux/debug_trace.hpp>
#elif defined _WIN32 || defined _WIN64
#include <hotplace/sdk/base/system/windows/debug_trace.hpp>
#endif
#include <hotplace/sdk/base/system/ieee754.hpp>
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
#include <hotplace/sdk/base/unittest/types.hpp>

#endif
