/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_TYPES__
#define __HOTPLACE_SDK_IO_ASN1_TYPES__

#include <hotplace/sdk/io/types.hpp>

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

enum asn1_bits_t : uint8 {
    // X.680 8.1.2.2 Table 1 - encoding of class of tag
    // class            bit8 bit7
    // universal        0    0
    // application      0    1
    // context-specific 1    0
    // private          1    1
    asn1_class_universal = 0x00,
    asn1_class_application = 0x40,
    asn1_class_context = 0x80,
    asn1_class_private = 0xc0,
    asn1_class_empty = asn1_class_context,
    asn1_class_mask = asn1_class_private,

    // X.680 8.1.2.3 Figure 3 - identifier octet
    // identifier       bit6
    // primitive        0
    // constructed      1
    asn1_tag_primitive = 0x00,
    asn1_tag_constructed = 0x20,
    asn1_tag_mask = asn1_tag_constructed,

    asn1_tag_number_mask = 0x1f,
};

static inline bool asn1_is_universal(uint8 c) { return asn1_class_universal == (c & asn1_class_mask); }
static inline bool asn1_is_application(uint8 c) { return asn1_class_application == (c & asn1_class_mask); }
static inline bool asn1_is_context(uint8 c) { return asn1_class_context == (c & asn1_class_mask); }
static inline bool asn1_is_private(uint8 c) { return asn1_class_private == (c & asn1_class_mask); }
static inline bool asn1_is_primitive(uint8 c) { return asn1_tag_primitive == (c & asn1_tag_mask); }
static inline bool asn1_is_constructed(uint8 c) { return asn1_tag_constructed == (c & asn1_tag_mask); }

enum asn1_entity_t {
    asn1_entity_boolean = asn1_tag_boolean,
    asn1_entity_integer = asn1_tag_integer,
    asn1_entity_bitstring = asn1_tag_bitstring,
    asn1_entity_octstring = asn1_tag_octstring,
    asn1_entity_null = asn1_tag_null,
    asn1_entity_objid = asn1_tag_objid,
    asn1_entity_objdesc = asn1_tag_objdesc,
    asn1_entity_extern = asn1_tag_extern,
    asn1_entity_real = asn1_tag_real,
    asn1_entity_enum = asn1_tag_enum,
    asn1_entity_embedpdv = asn1_tag_embedpdv,
    asn1_entity_utf8string = asn1_tag_utf8string,
    asn1_entity_reloid = asn1_tag_relobjid,
    asn1_entity_sequence = asn1_tag_sequence,
    asn1_entity_set = asn1_tag_set,
    asn1_entity_numstring = asn1_tag_numstring,
    asn1_entity_printstring = asn1_tag_printstring,
    asn1_entity_teletexstring = asn1_tag_teletexstring,
    asn1_entity_t61string = asn1_tag_teletexstring,
    asn1_entity_videotexstring = asn1_tag_videotexstring,
    asn1_entity_ia5string = asn1_tag_ia5string,
    asn1_entity_utctime = asn1_tag_utctime,
    asn1_entity_generalizedtime = asn1_tag_generalizedtime,
    asn1_entity_graphicstring = asn1_tag_graphicstring,
    asn1_entity_visiblestring = asn1_tag_visiblestring,
    asn1_entity_iso646string = asn1_tag_visiblestring,
    asn1_entity_generalstring = asn1_tag_generalstring,
    asn1_entity_universalstring = asn1_tag_universalstring,
    asn1_entity_cstring = asn1_tag_cstring,
    asn1_entity_bmpstring = asn1_tag_bmpstring,
    asn1_entity_date = asn1_tag_date,
    asn1_entity_timeofday = asn1_tag_timeofday,
    asn1_entity_datetime = asn1_tag_datetime,
    asn1_entity_duration = asn1_tag_duration,

    asn1_entity_builtin_type = 0x1000,
    // ReferencedType ::= DefinedType | UsefulType | SelectionType | TypeFromObject | ValueSetFromObjects -- type assignment
    asn1_entity_referenced_type,
    // TaggedType ::= Tag Type | Tag IMPLICIT Type | Tag EXPLICIT Type
    // Tag ::= "[" Class ClassNumber "]"
    asn1_entity_tag,
    asn1_entity_tagged_type,
    // NamedType ::= identifier Type
    asn1_entity_named_type,
    // SequenceOfType ::= SEQUENCE OF Type | SEQUENCE OF NamedType
    asn1_entity_sequence_of,
    // SetOfType ::= SET OF Type | SET OF NamedType
    asn1_entity_set_of,
    asn1_entity_choice,
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

enum asn1_perm_t : uint8 {
    asn1_perm_none = 0,
    asn1_perm_primitive = 1 << 0,
    asn1_perm_constructed = 1 << 1,
    asn1_perm_both = (asn1_perm_primitive | asn1_perm_constructed),
};

class asn1_object;
class asn1_type;
class asn1_builtin_type;
class asn1_referenced_type;

class asn1_container;
class asn1_encode;
class asn1_resource;
class asn1_sequence;
class asn1_sequence_of;
class asn1_set;
class asn1_set_of;
class asn1_tag;
class asn1_value;
class asn1_visitor;
class asn1_der_visitor;
class asn1_notation_visitor;

}  // namespace io
}  // namespace hotplace

#endif
