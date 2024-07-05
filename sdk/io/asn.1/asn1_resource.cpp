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
        struct builtintypes {
            asn1_type_t type;
            const char* type_name;
        } _types[] = {
            {asn1_type_boolean, "BOOLEAN"},
            {asn1_type_integer, "INTEGER"},
            {asn1_type_bitstring, "BIT STRING"},
            {asn1_type_octstring, "OCTET STRING"},
            {asn1_type_null, "NULL"},
            {asn1_type_objid, "OBJECT IDENTIFIER"},
            {asn1_type_objdesc, "ObjectDescriptor"},
            {asn1_type_extern, "EXTERNAL"},
            {asn1_type_real, "REAL"},
            {asn1_type_enum, "ENUMERATED"},
            {asn1_type_embedpdv, "EMBEDDED PDV"},
            {asn1_type_utf8string, "UTF8String"},
            {asn1_type_relobjid, "RELATIVE-OID"},
            {asn1_type_sequence, "SEQUENCE"},
            {asn1_type_sequence_of, "SEQUENCE OF"},
            {asn1_type_set, "SET"},
            {asn1_type_set_of, "SET OF"},
            {asn1_type_numstring, "NumericString"},
            {asn1_type_printstring, "PrintableString"},
            {asn1_type_teletexstring, "TeletexString"},
            {asn1_type_videotexstring, "VideotexString"},
            {asn1_type_ia5string, "IA5String"},
            {asn1_type_utctime, "UTCTime"},
            {asn1_type_generalizedtime, "GeneralizedTime"},
            {asn1_type_graphicstring, "GraphicString"},
            {asn1_type_visiblestring, "VisibleString"},
            {asn1_type_generalstring, "GeneralString"},
            {asn1_type_universalstring, "UniversalString"},
            {asn1_type_cstring, "CHARACTER STRING"},
            {asn1_type_bmpstring, "BMPString"},
            {asn1_type_date, "DATE"},
        };
        for (auto item : _types) {
            _type_id.insert({item.type, item.type_name});
            _type_rid.insert({item.type_name, item.type});
        }

        _class_id.insert({asn1_class_universal, "UNIVERSAL"});
        _class_id.insert({asn1_class_application, "APPLICATION"});
        _class_id.insert({asn1_class_private, "PRIVATE"});
        // _class_id.insert({asn1_class_empty, ""});
    }
}  // namespace io

std::string asn1_resource::get_type_name(asn1_type_t t) {
    load_resource();

    std::string name;
    auto iter = _type_id.find(t);
    if (_type_id.end() != iter) {
        name = iter->second;
    }
    return name;
}

asn1_type_t asn1_resource::get_type(const std::string& name) {
    load_resource();

    asn1_type_t type = asn1_type_primitive;
    auto iter = _type_rid.find(name);
    if (_type_rid.end() != iter) {
        type = iter->second;
    }
    return type;
}

std::string asn1_resource::get_class_name(int c) {
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

void asn1_resource::for_each_type_name(std::function<void(asn1_type_t, const std::string&)> f) {
    if (f) {
        for (auto item : _type_id) {
            f(item.first, item.second);
        }
    }
}

}  // namespace io
}  // namespace hotplace
