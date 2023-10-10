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
#include <hotplace/sdk/io/basic/json.hpp>
#include <hotplace/sdk/io/basic/keyvalue.hpp>
#include <hotplace/sdk/io/basic/mlfq.hpp>
#include <hotplace/sdk/io/basic/obfuscate_string.hpp>
#include <hotplace/sdk/io/basic/zlib.hpp>
#include <hotplace/sdk/io/cbor/cbor_array.hpp>
#include <hotplace/sdk/io/cbor/cbor_data.hpp>
#include <hotplace/sdk/io/cbor/cbor_encode.hpp>
#include <hotplace/sdk/io/cbor/cbor_map.hpp>
#include <hotplace/sdk/io/cbor/cbor_object.hpp>
#include <hotplace/sdk/io/cbor/cbor_publisher.hpp>
#include <hotplace/sdk/io/cbor/cbor_reader.hpp>
#include <hotplace/sdk/io/cbor/cbor_visitor.hpp>
#include <hotplace/sdk/io/stream/file_stream.hpp>
#include <hotplace/sdk/io/stream/stream.hpp>
#include <hotplace/sdk/io/stream/string.hpp>
#include <hotplace/sdk/io/string/string.hpp>
#include <hotplace/sdk/io/system/multiplexer.hpp>
#include <hotplace/sdk/io/system/sdk.hpp>
#include <hotplace/sdk/io/system/types.hpp>
#include <hotplace/sdk/io/types.hpp>
#if defined __linux__
#elif defined _WIN32 || defined _WIN64
#include <hotplace/sdk/io/system/windows/windows_registry.hpp>
#endif
#include <hotplace/sdk/io/unittest/testcase.hpp>

#endif
