/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   cbor.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7049 Concise Binary Object Representation (CBOR)
 *  RFC 8949 Concise Binary Object Representation (CBOR)
 *
 * Revision History
 * Date         Name                Description
 *
 * @example
 *      cbor_array* root = new cbor_array ();
 *      *root << new cbor_data (1) << new cbor_data (2);
 *
 *      cbor_publisher publisher;
 *      basic_stream diagnostic;
 *      binary_t bin;
 *      // cbor_object* to diagnostic
 *      publisher.publish (root, &diagnostic);
 *      // cbor_object* to cbor
 *      publisher.publish (root, &bin);
 *
 *      // cbor_reader_context_t*
 *      cbor_reader reader;
 *      cbor_reader_context_t* handle = nullptr;
 *      reader.open (&handle);
 *      reader.parse (handle, bin);
 *      // cbor_reader_context_t* to diagnostic
 *      reader.publish (handle, &diagnostic2);
 *      // cbor_reader_context_t* to cbor
 *      reader.publish (handle, &bin2);
 *      // cbor_reader_context_t* to cbor_object*
 *      cbor_object* newone = nullptr;
 *      reader.publish (handle, &newone);
 *      newone->release (); // free
 *      reader.close (handle);
 *
 *      root->release (); // free
 */

#ifndef __HOTPLACE_SDK_IO_CBOR_CBOR__
#define __HOTPLACE_SDK_IO_CBOR_CBOR__

#include <deque>
#include <hotplace/sdk/base/stream/printf.hpp>
#include <hotplace/sdk/base/system/endian.hpp>
#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/system/types.hpp>

namespace hotplace {
namespace io {

enum class cbor_major_t {
    uint = 0,    ///<< 0000 0
    nint = 1,    ///<< 0010 2
    bstr = 2,    ///<< 0100 4, 0101 1111 5f (indefinite-length)
    tstr = 3,    ///<< 0110 6, 0111 1111 7f (indefinite-length)
    array = 4,   ///<< 1000 8, 1001 1111 9f (indefinite-length)
    map = 5,     ///<< 1010 a, 1011 1111 bf (indefinite-length)
    tag = 6,     ///<< 1100 c
    fp = 7,      ///<< 1110 e
    simple = 7,  ///<< 111x e or f, see additional info
};

enum class cbor_tag_t {
    unknown = -1,
    std_datetime = 0,
    epoch_datetime = 1,
    positive_bignum = 2,
    negative_bignum = 3,
    decimal_fraction = 4,
    big_float = 5,
    base64url = 21,
    base64 = 22,
    base16 = 23,
    encoded = 24,
    uri = 32,
    base64url_utf8 = 33,
    base64_utf8 = 34,
    regex_utf8 = 35,
    mime_utf8 = 36,

    // RFC 8152 Table 1: COSE Message Identification
    // RFC 9052 Table 1: COSE Message Identification
    sign = 98,      // COSE Signed Data Object
    sign1 = 18,     // COSE Single Signer Data Object
    encrypt = 96,   // COSE Encrypted Data Object
    encrypt0 = 16,  // OSE Single Recipient Encrypted Data Object
    mac = 97,       // COSE MACed Data Object
    mac0 = 17,      // COSE Mac w/o Recipients Object
};

enum class cbor_type_t {
    null = 0,
    array = 1,
    data = 2,
    pair = 3,  // keyvalue
    map = 4,   // keyvalues
    simple = 5,
    bstrs = 6,
    tstrs = 7,
};

/*
 * @desc
 *      RFC 8949 Concise Binary Object Representation (CBOR)
 *      An encoder MUST NOT issue two-byte sequences that start with 0xf8
 *      (major type 7, additional information 24) and continue with a byte
 *      less than 0x20 (32 decimal).
 */
enum class cbor_simple_t {
    unknown = 0,        // Not applicable, not a type, ...
    value = 19,         // additional info 0..19 : unassigned
                        // additional info 24 : following byte (value 32-255)
    _false = 20,        // additional info 20 : false
    _true = 21,         // additional info 21 : true
    null = 22,          // additional info 22 : null
    undef = 23,         // additional info 23 : undefined value
    half_fp = 25,       // additional info 25 : half-precision floaing point
    single_fp = 26,     // additional info 26 : single-precision floaing point
    double_fp = 27,     // additional info 27 : double-precision floaing point
    reserved = 30,      // additional info 28-30 : unassigned
    simple_break = 31,  // additional info 31 : break
};

enum cbor_control_t {
    cbor_control_begin = 0,
    cbor_control_end,
};

enum cbor_flag_t {
    cbor_indef = 1,  // indefinite-length
};

struct _cbor_reader_context_t;
typedef struct _cbor_reader_context_t cbor_reader_context_t;

class cbor_array;
class cbor_bstrings;
class cbor_concise_visitor;
class cbor_data;
class cbor_diagnostic_visitor;
class cbor_encode;
class cbor_map;
class cbor_object;
class cbor_pair;
class cbor_publisher;
class cbor_reader;
class cbor_tstrings;
class cbor_visitor;

}  // namespace io
}  // namespace hotplace

#endif
