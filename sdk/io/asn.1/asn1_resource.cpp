/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <sdk/io/asn.1/asn1.hpp>

namespace hotplace {
namespace io {

asn1_resource asn1_resource::_instance;

asn1_resource::asn1_resource() {}

asn1_resource* asn1_resource::get_instance() { return &_instance; }

void asn1_resource::load_resource() {
    if (_type_id.empty()) {
        _type_id.insert({asn1_type_choice, "CHOICE"});
        _type_id.insert({asn1_type_enum, "ENUMERATED"});
        _type_id.insert({asn1_type_integer, "INTEGER"});
        _type_id.insert({asn1_type_null, "NULL"});
        _type_id.insert({asn1_type_real, "REAL"});
        _type_id.insert({asn1_type_sequence, "SEQUENCE"});
        _type_id.insert({asn1_type_sequence_of, "SEQUENCE OF"});
        _type_id.insert({asn1_type_set, "SET"});
        _type_id.insert({asn1_type_set_of, "SET OF"});
        _type_id.insert({asn1_type_bitstring, "BIT STRING"});
        _type_id.insert({asn1_type_boolean, "BOOLEAN"});
        _type_id.insert({asn1_type_bmpstring, "BMPString"});
        _type_id.insert({asn1_type_generalstring, "GeneralString"});
        _type_id.insert({asn1_type_graphicstring, "GraphicString"});
        _type_id.insert({asn1_type_ia5string, "IA5String"});
        _type_id.insert({asn1_type_iso646string, "ISO646String"});
        _type_id.insert({asn1_type_numericstring, "NumericString"});
        _type_id.insert({asn1_type_printablestring, "PrintableString"});
        _type_id.insert({asn1_type_teletexstring, "TeletexString"});
        _type_id.insert({asn1_type_t61string, "T61String"});
        _type_id.insert({asn1_type_universalstring, "UniversalString"});
        _type_id.insert({asn1_type_utf8string, "UTF8String"});
        _type_id.insert({asn1_type_videotexstring, "VideotexString"});
        _type_id.insert({asn1_type_visiblestring, "VisibleString"});

        _class_id.insert({asn1_class_universal, "UNIVERSAL"});
        _class_id.insert({asn1_class_application, "APPLICATION"});
        _class_id.insert({asn1_class_private, "PRIVATE"});
        // _class_id.insert({asn1_class_empty, ""});
    }
}

std::string asn1_resource::get_type_name(asn1_type_t t) {
    load_resource();

    std::string name;
    auto iter = _type_id.find(t);
    if (_type_id.end() != iter) {
        name = iter->second;
    }
    return name;
}

std::string asn1_resource::get_class_name(asn1_class_t c) {
    load_resource();

    std::string name;
    auto iter = _class_id.find(c);
    if (_class_id.end() != iter) {
        name = iter->second;
    }
    return name;
}

std::string asn1_resource::get_tagtype_name(uint32 t) {
    std::string name;
    switch (t) {
        case asn1_implicit:
            name = "IMPLICIT";
            break;
        case asn1_explicit:
            name = "EXPLICIT";
            break;
    }
    return name;
}

std::string asn1_resource::get_componenttype_name(uint32 t) {
    std::string name;
    switch (t) {
        case asn1_default:
            name = "DEFAULT";
            break;
        case asn1_optional:
            name = "OPTIONAL";
            break;
    }
    return name;
}

}  // namespace io
}  // namespace hotplace
