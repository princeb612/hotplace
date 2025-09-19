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
#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/io/types.hpp>

/* basic */
#include <hotplace/sdk/io/basic/json.hpp>
#include <hotplace/sdk/io/basic/mlfq.hpp>
#include <hotplace/sdk/io/basic/oid.hpp>
#include <hotplace/sdk/io/basic/parser.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/io/basic/types.hpp>
#include <hotplace/sdk/io/basic/zlib.hpp>

/* CBOR */
#include <hotplace/sdk/io/cbor/cbor.hpp>
#include <hotplace/sdk/io/cbor/cbor_array.hpp>
#include <hotplace/sdk/io/cbor/cbor_bignum.hpp>
#include <hotplace/sdk/io/cbor/cbor_bstrings.hpp>
#include <hotplace/sdk/io/cbor/cbor_data.hpp>
#include <hotplace/sdk/io/cbor/cbor_encode.hpp>
#include <hotplace/sdk/io/cbor/cbor_map.hpp>
#include <hotplace/sdk/io/cbor/cbor_object.hpp>
#include <hotplace/sdk/io/cbor/cbor_pair.hpp>
#include <hotplace/sdk/io/cbor/cbor_publisher.hpp>
#include <hotplace/sdk/io/cbor/cbor_reader.hpp>
#include <hotplace/sdk/io/cbor/cbor_simple.hpp>
#include <hotplace/sdk/io/cbor/cbor_tstrings.hpp>
#include <hotplace/sdk/io/cbor/cbor_visitor.hpp>

/* stream */
#include <hotplace/sdk/io/stream/file_stream.hpp>
#include <hotplace/sdk/io/stream/stream.hpp>
#include <hotplace/sdk/io/stream/string.hpp>
#include <hotplace/sdk/io/stream/types.hpp>

/* string */
#include <hotplace/sdk/io/string/string.hpp>

/* system */
#include <hotplace/sdk/io/system/multiplexer.hpp>
#include <hotplace/sdk/io/system/sdk.hpp>
#include <hotplace/sdk/io/system/socket.hpp>
#include <hotplace/sdk/io/system/types.hpp>
#include <hotplace/sdk/io/system/winpe.hpp>
#if defined __linux__
#include <hotplace/sdk/io/system/linux/netlink.hpp>
#elif defined _WIN32 || defined _WIN64
#include <hotplace/sdk/io/system/windows/windows_registry.hpp>
#endif

/* asn.1 */
#include <hotplace/sdk/io/asn.1/asn1.hpp>
#include <hotplace/sdk/io/asn.1/asn1_composite.hpp>
#include <hotplace/sdk/io/asn.1/asn1_container.hpp>
#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/asn1_sequence.hpp>
#include <hotplace/sdk/io/asn.1/asn1_set.hpp>
#include <hotplace/sdk/io/asn.1/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/asn1_visitor.hpp>
#include <hotplace/sdk/io/asn.1/template.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>

#endif
