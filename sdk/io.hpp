/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file    io.hpp
 * @author  Soo Han, Kim (princeb612.kr@gmail.com)
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
#include <sdk/io/basic/oid.hpp>
#include <sdk/io/basic/parser.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/io/basic/types.hpp>
#include <sdk/io/basic/zlib.hpp>

/* CBOR */
#include <sdk/io/cbor/cbor.hpp>
#include <sdk/io/cbor/cbor_array.hpp>
#include <sdk/io/cbor/cbor_bignum.hpp>
#include <sdk/io/cbor/cbor_bstrings.hpp>
#include <sdk/io/cbor/cbor_data.hpp>
#include <sdk/io/cbor/cbor_encode.hpp>
#include <sdk/io/cbor/cbor_map.hpp>
#include <sdk/io/cbor/cbor_object.hpp>
#include <sdk/io/cbor/cbor_pair.hpp>
#include <sdk/io/cbor/cbor_publisher.hpp>
#include <sdk/io/cbor/cbor_reader.hpp>
#include <sdk/io/cbor/cbor_simple.hpp>
#include <sdk/io/cbor/cbor_tstrings.hpp>
#include <sdk/io/cbor/cbor_visitor.hpp>

/* stream */
#include <sdk/base/stream/split.hpp>
#include <sdk/io/stream/file_stream.hpp>
#include <sdk/io/stream/stream.hpp>
#include <sdk/io/stream/string.hpp>
#include <sdk/io/stream/types.hpp>

/* string */
#include <sdk/io/string/string.hpp>

/* system */
#include <sdk/io/system/multiplexer.hpp>
#include <sdk/io/system/sdk.hpp>
#include <sdk/io/system/socket.hpp>
#include <sdk/io/system/types.hpp>
#include <sdk/io/system/winpe.hpp>
#if defined __linux__
#include <sdk/io/system/linux/netlink.hpp>
#elif defined _WIN32 || defined _WIN64
#include <sdk/io/system/windows/windows_registry.hpp>
#endif

/* asn.1 */
#include <sdk/io/asn.1/asn1.hpp>
#include <sdk/io/asn.1/asn1_composite.hpp>
#include <sdk/io/asn.1/asn1_container.hpp>
#include <sdk/io/asn.1/asn1_encode.hpp>
#include <sdk/io/asn.1/asn1_object.hpp>
#include <sdk/io/asn.1/asn1_resource.hpp>
#include <sdk/io/asn.1/asn1_sequence.hpp>
#include <sdk/io/asn.1/asn1_set.hpp>
#include <sdk/io/asn.1/asn1_tag.hpp>
#include <sdk/io/asn.1/asn1_visitor.hpp>
#include <sdk/io/asn.1/template.hpp>
#include <sdk/io/asn.1/types.hpp>

#endif
