/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_TYPES__
#define __HOTPLACE_SDK_IO_ASN1_TYPES__

#include <sdk/io/types.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   ASN.1 Tags
 * @sa
 *          X.680 8.4 Table 1 – Universal class tag assignments
 *          https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference.html
 *          https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference/asn1-tags.html
 */
enum asn1_tag_t {
    asn1_tag_boolean = 1,           // BOOLEAN
    asn1_tag_integer = 2,           // INTEGER
    asn1_tag_bitstring = 3,         // BIT STRING
    asn1_tag_octstring = 4,         // OCTET STRING
    asn1_tag_null = 5,              // NULL
    asn1_tag_objid = 6,             // OBJECT IDENTIFIER
    asn1_tag_objdesc = 7,           // ObjectDescriptor
    asn1_tag_extern = 8,            // EXTERNAL
    asn1_tag_real = 9,              // REAL
    asn1_tag_enum = 10,             // ENUMERATED
    asn1_tag_embedpdv = 11,         // EMBEDDED PDV
    asn1_tag_utf8string = 12,       // UTF8String
    asn1_tag_relobjid = 13,         // RELATIVE-OID
    asn1_tag_time = 14,             // TIME
    asn1_tag_sequence = 16,         // SEQUENCE, SEQUENCE OF
    asn1_tag_set = 17,              // SET, SET OF
    asn1_tag_numstring = 18,        // NumericString
    asn1_tag_printstring = 19,      // PrintableString
    asn1_tag_teletexstring = 20,    // TeletexString, T61String
    asn1_tag_videotexstring = 21,   // VideotexString
    asn1_tag_ia5string = 22,        // IA5String
    asn1_tag_utctime = 23,          // UTCTime
    asn1_tag_generalizedtime = 24,  // GeneralizedTime
    asn1_tag_graphicstring = 25,    // GraphicString
    asn1_tag_visiblestring = 26,    // VisibleString, ISO646String
    asn1_tag_generalstring = 27,    // GeneralString
    asn1_tag_universalstring = 28,  // UniversalString
    asn1_tag_cstring = 29,          // CHARACTER STRING
    asn1_tag_bmpstring = 30,        // BMPString
    asn1_tag_date = 31,             // DATE
    asn1_tag_timeofday = 32,        // TIME-OF-DAY
    asn1_tag_datetime = 33,         // DATE-TIME
    asn1_tag_duration = 34,         // DURATION

};

enum asn1_bits_t {
    // X.680 8.1.2.2 Table 1 - encoding of class of tag
    // class            bit8 bit7
    // universal        0    0
    // application      0    1
    // context-specific 1    0
    // private          1    1
    asn1_class_universal = 0x00,
    asn1_class_application = 0x40,
    asn1_class_context = 0x80,
    asn1_class_empty = asn1_class_context,
    asn1_class_private = 0xc0,

    // X.680 8.1.2.3 Figure 3 - identifier octet
    // identifier       bit6
    // primitive        0
    // constructed      1
    asn1_tag_primitive = 0x00,
    asn1_tag_constructed = 0x20,
};

enum asn1_type_t {
    asn1_type_special = 0x1000,
    asn1_type_primitive = 0,
    asn1_type_constructed = (asn1_type_special + 1),
    asn1_type_referenced = (asn1_type_special + 2),

    // TaggedType ::= Tag Type | Tag IMPLICIT Type | Tag EXPLICIT Type
    // Tag ::= "[" Class ClassNumber "]"
    asn1_type_tagged = (asn1_type_special + 3),
    // NamedType ::= identifier Type
    asn1_type_named = (asn1_type_special + 4),

    asn1_type_boolean = asn1_tag_boolean,
    asn1_type_integer = asn1_tag_integer,
    asn1_type_bitstring = asn1_tag_bitstring,
    asn1_type_octstring = asn1_tag_octstring,
    asn1_type_null = asn1_tag_null,
    asn1_type_objid = asn1_tag_objid,
    asn1_type_objdesc = asn1_tag_objdesc,
    asn1_type_extern = asn1_tag_extern,
    asn1_type_real = asn1_tag_real,
    asn1_type_enum = asn1_tag_enum,
    asn1_type_embedpdv = asn1_tag_embedpdv,
    asn1_type_utf8string = asn1_tag_utf8string,
    asn1_type_reloid = asn1_tag_relobjid,
    asn1_type_sequence = asn1_tag_sequence,
    asn1_type_sequence_of = (asn1_type_special + 5),
    asn1_type_set = asn1_tag_set,
    asn1_type_set_of = (asn1_type_special + 6),
    asn1_type_numstring = asn1_tag_numstring,
    asn1_type_printstring = asn1_tag_printstring,
    asn1_type_teletexstring = asn1_tag_teletexstring,
    asn1_type_t61string = asn1_tag_teletexstring,
    asn1_type_videotexstring = asn1_tag_videotexstring,
    asn1_type_ia5string = asn1_tag_ia5string,
    asn1_type_utctime = asn1_tag_utctime,
    asn1_type_generalizedtime = asn1_tag_generalizedtime,
    asn1_type_graphicstring = asn1_tag_graphicstring,
    asn1_type_visiblestring = asn1_tag_visiblestring,
    asn1_type_iso646string = asn1_tag_visiblestring,
    asn1_type_generalstring = asn1_tag_generalstring,
    asn1_type_universalstring = asn1_tag_universalstring,
    asn1_type_cstring = asn1_tag_cstring,
    asn1_type_bmpstring = asn1_tag_bmpstring,
    asn1_type_date = asn1_tag_date,
    asn1_type_timeofday = asn1_tag_timeofday,
    asn1_type_datetime = asn1_tag_datetime,
    asn1_type_duration = asn1_tag_duration,
};

enum asn1_tagtype_t {
    // tagging mode
    asn1_automatic = 0,
    asn1_implicit = 1,
    asn1_explicit = 2,

    // component type
    asn1_default = 3,
    asn1_optional = 4,
};

}  // namespace io
}  // namespace hotplace

#endif
