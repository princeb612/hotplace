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

#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {
namespace io {

enum asn1_type_t {
    asn1_type_unknown = 0,
    asn1_type_tag,
    asn1_type_pair,

    asn1_type_choice,
    asn1_type_enum,
    asn1_type_integer,
    asn1_type_null,
    asn1_type_real,
    asn1_type_sequence,
    asn1_type_sequence_of,
    asn1_type_set,
    asn1_type_set_of,

    asn1_type_bitstring,
    asn1_type_boolean,
    asn1_type_bmpstring,
    asn1_type_generalstring,
    asn1_type_graphicstring,
    asn1_type_ia5string,
    asn1_type_iso646string,
    asn1_type_numericstring,
    asn1_type_printablestring,
    asn1_type_teletexstring,
    asn1_type_t61string,
    asn1_type_universalstring,
    asn1_type_utf8string,
    asn1_type_videotexstring,
    asn1_type_visiblestring,

    asn1_type_generalizedtime,
    asn1_type_utctime,
};

enum asn1_class_t {
    asn1_class_universal = 1,
    asn1_class_application,
    asn1_class_private,
    asn1_class_empty,
};

// X.680 8.4 Table 1 – Universal class tag assignments
enum asn1_tag_t {
    asn1_tag_boolean = 1,
    asn1_tag_integer = 2,
    asn1_tag_bitstring = 3,
    asn1_tag_octstring = 4,
    asn1_tag_null = 5,
    asn1_tag_objid = 6,
    asn1_tag_objdesc = 7,
    asn1_tag_extern = 8,
    asn1_tag_real = 9,
    asn1_tag_enum = 10,
    asn1_tag_embedpdv = 11,
    asn1_tag_utf8string = 12,
    asn1_tag_relobjid = 13,
    asn1_tag_sequence = 16,
    asn1_tag_set = 17,
    asn1_tag_numstring = 18,       // NumericString
    asn1_tag_printstring = 19,     // PrintableString
    asn1_tag_teletexstring = 20,   // TeletexString(T61String)
    asn1_tag_videotexstring = 21,  // VideotexString
    asn1_tag_ia5string = 0x16,     // IA5String
    asn1_tag_time = 23,
    asn1_tag_graphicstring = 25,    // GraphicString
    asn1_tag_visiblestring = 0x1a,  // VisibleString(ISO646String)
    asn1_tag_generalstring = 27,    // GenetalString
    asn1_tag_universalstring = 28,  // UniversalString
    asn1_tag_bmpstring = 30,        // BMPString

    // X.680 8.1.2.2 Table 1 - encoding of class of tag
    // class            bit8 bit7
    // primitive        0    0
    // application      0    1
    // context-specific 1    0
    // private          1    1
    asn1_tag_universal = 0x00,
    asn1_tag_application = 0x40,
    asn1_tag_context = 0x80,
    asn1_tag_private = 0xc0,

    // X.680 8.1.2.3 Figure 3 - identifier octet
    // identifier       bit6
    // primitive        0
    // constructed      1
    asn1_tag_primitive = 0x00,
    asn1_tag_constructed = 0x20,
};

enum asn1_tagtype_t {
    // tag type
    asn1_implicit = 1,
    asn1_explicit = 2,

    // component type
    asn1_default = 3,
    asn1_optional = 4,
};

struct oid_t {
    // ITU-T X.660 ISO/IEC 9834-1, ISO/IEC 6523 Structure for the identification of organizations and organization parts
    uint8 node1;      // 0, 1, 2
    uint8 node2;      // 0..39
    uint32 node[16];  // positive
};

struct reloid_t {
    uint32 node[16];  // positive
};

}  // namespace io
}  // namespace hotplace

#endif
