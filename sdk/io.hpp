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

/* top-most */
#include <sdk/base.hpp>
#include <sdk/io/types.hpp>

/* basic */
#include <sdk/io/basic/json.hpp>
#include <sdk/io/basic/mlfq.hpp>
#include <sdk/io/basic/parser.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/io/basic/zlib.hpp>
#include <sdk/io/system/socket.hpp>

/* CBOR */
#include <sdk/io/cbor/cbor_array.hpp>
#include <sdk/io/cbor/cbor_data.hpp>
#include <sdk/io/cbor/cbor_encode.hpp>
#include <sdk/io/cbor/cbor_map.hpp>
#include <sdk/io/cbor/cbor_object.hpp>
#include <sdk/io/cbor/cbor_publisher.hpp>
#include <sdk/io/cbor/cbor_reader.hpp>
#include <sdk/io/cbor/cbor_visitor.hpp>
#include <sdk/io/cbor/concise_binary_object_representation.hpp>

/* stream */
#include <sdk/io/stream/file_stream.hpp>
#include <sdk/io/stream/stream.hpp>
#include <sdk/io/stream/string.hpp>

/* string */
#include <sdk/io/string/string.hpp>

/* system */
#include <sdk/io/system/multiplexer.hpp>
#include <sdk/io/system/sdk.hpp>
#include <sdk/io/system/types.hpp>
#include <sdk/io/system/winpe.hpp>
#if defined __linux__
#include <sdk/io/system/linux/netlink.hpp>
#elif defined _WIN32 || defined _WIN64
#include <sdk/io/system/windows/windows_registry.hpp>
#endif

#endif
