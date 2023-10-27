/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
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

#ifndef __HOTPLACE_SDK_IO_CBOR__
#define __HOTPLACE_SDK_IO_CBOR__

#include <deque>
#include <sdk/base.hpp>
#include <sdk/io/stream/stream.hpp>

namespace hotplace {
namespace io {

enum cbor_major_t {
    cbor_major_uint = 0,    ///<< 0000 0
    cbor_major_nint = 1,    ///<< 0010 2
    cbor_major_bstr = 2,    ///<< 0100 4, 0101 1111 5f (indefinite-length)
    cbor_major_tstr = 3,    ///<< 0110 6, 0111 1111 7f (indefinite-length)
    cbor_major_array = 4,   ///<< 1000 8, 1001 1111 9f (indefinite-length)
    cbor_major_map = 5,     ///<< 1010 a, 1011 1111 bf (indefinite-length)
    cbor_major_tag = 6,     ///<< 1100 c
    cbor_major_float = 7,   ///<< 1110 e
    cbor_major_simple = 7,  ///<< 111x e or f, see additional info
};

enum cbor_tag_t {
    cbor_tag_unknown = -1,
    cbor_tag_std_datetime = 0,
    cbor_tag_epoch_datetime = 1,
    cbor_tag_positive_bignum = 2,
    cbor_tag_negative_bignum = 3,
    cbor_tag_decimal_fraction = 4,
    cbor_tag_big_float = 5,
    cbor_tag_base64url = 21,
    cbor_tag_base64 = 22,
    cbor_tag_base16 = 23,
    cbor_tag_encoded = 24,
    cbor_tag_uri = 32,
    cbor_tag_base64url_utf8 = 33,
    cbor_tag_base64_utf8 = 34,
    cbor_tag_regex_utf8 = 35,
    cbor_tag_mime_utf8 = 36,

    // RFC 8152 Table 1: COSE Message Identification
    // RFC 9052 Table 1: COSE Message Identification
    cose_tag_sign = 98,      // COSE Signed Data Object
    cose_tag_sign1 = 18,     // COSE Single Signer Data Object
    cose_tag_encrypt = 96,   // COSE Encrypted Data Object
    cose_tag_encrypt0 = 16,  // OSE Single Recipient Encrypted Data Object
    cose_tag_mac = 97,       // COSE MACed Data Object
    cose_tag_mac0 = 17,      // COSE Mac w/o Recipients Object
};

enum cbor_type_t {
    cbor_type_null = 0,
    cbor_type_array = 1,
    cbor_type_data = 2,
    cbor_type_pair = 3,  // keyvalue
    cbor_type_map = 4,   // keyvalues
    cbor_type_simple = 5,
    cbor_type_bstrs = 6,
    cbor_type_tstrs = 7,
};

/*
 * @desc
 *      RFC 8949 Concise Binary Object Representation (CBOR)
 *      An encoder MUST NOT issue two-byte sequences that start with 0xf8
 *      (major type 7, additional information 24) and continue with a byte
 *      less than 0x20 (32 decimal).
 */
enum cbor_simple_t {
    cbor_simple_error = 0,       // Not applicable, not a type, ...
    cbor_simple_value = 19,      // additional info 0..19 : unassigned
                                 // additional info 24 : following byte (value 32-255)
    cbor_simple_false = 20,      // additional info 20 : false
    cbor_simple_true = 21,       // additional info 21 : true
    cbor_simple_null = 22,       // additional info 22 : null
    cbor_simple_undef = 23,      // additional info 23 : undefined value
    cbor_simple_half_fp = 25,    // additional info 25 : half-precision floaing point
    cbor_simple_single_fp = 26,  // additional info 26 : single-precision floaing point
    cbor_simple_double_fp = 27,  // additional info 27 : double-precision floaing point
    cbor_simple_reserved = 30,   // additional info 28-30 : unassigned
    cbor_simple_break = 31,      // additional info 31 : break
};

enum cbor_control_t {
    cbor_control_begin = 0,
    cbor_control_end,
};

enum cbor_flag_t {
    cbor_indef = 1,  // indefinite-length
};

class cbor_object;
class cbor_data;
class cbor_bstrings;
class cbor_tstrings;
class cbor_pair;
class cbor_map;
class cbor_array;
class cbor_visitor;

}  // namespace io
}  // namespace hotplace

#endif
