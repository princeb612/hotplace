/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_resource.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

// #include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/string/string.hpp>  // format
// #include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_resource.hpp>

namespace hotplace {
namespace io {

asn1_resource asn1_resource::_instance;

asn1_resource::asn1_resource() {}

asn1_resource* asn1_resource::get_instance() {
    _instance.load_resource();
    return &_instance;
}

void asn1_resource::load_resource() {
    if (_type_id.empty()) {
        critical_section_guard guard(_lock);
        if (_type_id.empty()) {
            doload_resource();
        }
    }
}

struct asn1_entity_resource_t {
    asn1_entity_t type;
    const char* token;
    asn1_perm_t permission;
};
static struct asn1_entity_resource_t resource_entities[] = {
    {asn1_entity_boolean, "BOOLEAN", asn1_perm_primitive},
    {asn1_entity_integer, "INTEGER", asn1_perm_primitive},
    {asn1_entity_bitstring, "BIT STRING", asn1_perm_both},
    {asn1_entity_octstring, "OCTET STRING", asn1_perm_both},
    {asn1_entity_null, "NULL", asn1_perm_primitive},
    {asn1_entity_oid, "OBJECT IDENTIFIER", asn1_perm_primitive},
    {asn1_entity_objdesc, "ObjectDescriptor", asn1_perm_primitive},
    {asn1_entity_extern, "EXTERNAL", asn1_perm_constructed},
    {asn1_entity_real, "REAL", asn1_perm_both},
    {asn1_entity_enum, "ENUMERATED", asn1_perm_primitive},
    {asn1_entity_embedpdv, "EMBEDDED PDV", asn1_perm_constructed},
    {asn1_entity_utf8string, "UTF8String", asn1_perm_both},
    {asn1_entity_reloid, "RELATIVE-OID", asn1_perm_primitive},
    {asn1_entity_sequence, "SEQUENCE", asn1_perm_constructed},
    {asn1_entity_sequence_of, "SEQUENCE OF", asn1_perm_constructed},
    {asn1_entity_set, "SET", asn1_perm_constructed},
    {asn1_entity_set_of, "SET OF", asn1_perm_constructed},
    {asn1_entity_numstring, "NumericString", asn1_perm_both},
    {asn1_entity_printstring, "PrintableString", asn1_perm_both},
    {asn1_entity_teletexstring, "TeletexString", asn1_perm_both},
    {asn1_entity_videotexstring, "VideotexString", asn1_perm_both},
    {asn1_entity_ia5string, "IA5String", asn1_perm_both},
    {asn1_entity_utctime, "UTCTime", asn1_perm_primitive},
    {asn1_entity_generalizedtime, "GeneralizedTime", asn1_perm_primitive},
    {asn1_entity_graphicstring, "GraphicString", asn1_perm_both},
    {asn1_entity_visiblestring, "VisibleString", asn1_perm_both},
    {asn1_entity_generalstring, "GeneralString", asn1_perm_both},
    {asn1_entity_universalstring, "UniversalString", asn1_perm_both},
    {asn1_entity_cstring, "CHARACTER STRING", asn1_perm_both},
    {asn1_entity_bmpstring, "BMPString", asn1_perm_both},
    {asn1_entity_date, "DATE", asn1_perm_primitive},
    {asn1_entity_timeofday, "TIME-OF-DAY", asn1_perm_primitive},
    {asn1_entity_datetime, "DATE-TIME", asn1_perm_primitive},
    {asn1_entity_duration, "DURATION", asn1_perm_primitive},
    {asn1_entity_choice, "CHOICE", asn1_perm_constructed},
    {asn1_entity_any, "ANY", asn1_perm_both},

    {asn1_entity_builtin_type, "builtin type", asn1_perm_none},
    {asn1_entity_named_type, "named type", asn1_perm_none},
    {asn1_entity_referenced_type, "referenced type", asn1_perm_none},
    {asn1_entity_tag, "tag", asn1_perm_none},
    {asn1_entity_tagged_type, "tagged type", asn1_perm_none},

    {asn1_entity_syntax, "::=", asn1_perm_none},
    {asn1_entity_syntax, "--", asn1_perm_none},
    {asn1_entity_syntax, "OF", asn1_perm_none},
    {asn1_entity_syntax, "TRUE", asn1_perm_none},
    {asn1_entity_syntax, "FALSE", asn1_perm_none},
    {asn1_entity_syntax, "tagged mode", asn1_perm_none},
    {asn1_entity_syntax, "class", asn1_perm_none},
    {asn1_entity_syntax, "UNIVERSAL", asn1_perm_none},
    {asn1_entity_syntax, "APPLICATION", asn1_perm_none},
    {asn1_entity_syntax, "PRIVATE", asn1_perm_none},
    {asn1_entity_syntax, "IMPLICIT", asn1_perm_none},
    {asn1_entity_syntax, "EXPLICIT", asn1_perm_none},
    {asn1_entity_syntax, "|", asn1_perm_none},
    {asn1_entity_syntax, "INTERSECTION", asn1_perm_none},
    {asn1_entity_syntax, "EXCEPT", asn1_perm_none},
    {asn1_entity_syntax, "ALL EXCEPT", asn1_perm_none},
    {asn1_entity_syntax, "DEFAULT", asn1_perm_none},
};

void asn1_resource::doload_resource() {
    if (_type_id.empty()) {
        for (const auto& item : resource_entities) {
            if (asn1_entity_syntax == item.type) continue;
            _type_id.emplace(item.type, item.token);
            _type_rid.emplace(item.token, item.type);
            _type_perm.emplace(item.type, item.permission);
        }

        _class_id.emplace(asn1_class_universal, "UNIVERSAL");
        _class_id.emplace(asn1_class_application, "APPLICATION");
        _class_id.emplace(asn1_class_private, "PRIVATE");
    }
}

std::string asn1_resource::get_component_entity_name(asn1_entity_t entity) const {
    std::string name;
    auto iter = _type_id.find(entity);
    if (_type_id.end() != iter) {
        name = iter->second;
    }
    return name;
}

std::string asn1_resource::get_entity_name(uint8 ident, asn1_entity_t entity) const {
    std::string name;
    auto c = (ident & asn1_class_mask);
    switch (c) {
        case asn1_class_universal: {
            auto iter = _type_id.find(entity);
            if (_type_id.end() != iter) {
                name = iter->second;
            } else {
                name = format("[UNIVERSAL %u]", (unsigned int)entity);
            }
        } break;
        case asn1_class_application: {
            name = format("[APPLICATION %u]", (unsigned int)entity);
        } break;
        case asn1_class_context: {
            name = format("[%u]", (unsigned int)entity);
        } break;
        case asn1_class_private: {
            name = format("[PRIVATE %u]", (unsigned int)entity);
        } break;
    }
    return name;
}

asn1_entity_t asn1_resource::get_entity(const std::string& name) const {
    asn1_entity_t entity = {};
    auto iter = _type_rid.find(name);
    if (_type_rid.end() != iter) {
        entity = iter->second;
    }
    return entity;
}

asn1_perm_t asn1_resource::get_perm(asn1_entity_t entity) const {
    auto iter = _type_perm.find(entity);
    return (_type_perm.end() == iter) ? asn1_perm_none : iter->second;
}

std::string asn1_resource::get_class_name(int c) const {
    std::string name;
    auto iter = _class_id.find(c & asn1_class_mask);
    if (_class_id.end() != iter) {
        name = iter->second;
    }
    return name;
}

std::string asn1_resource::get_tagtype_name(uint16 t) const {
    std::string name;
    switch (t) {
        case asn1_implicit:
            name = "IMPLICIT";
            break;
        case asn1_explicit:
            name = "EXPLICIT";
            break;
        case asn1_default:
            name = "DEFAULT";
            break;
        case asn1_optional:
            name = "OPTIONAL";
            break;
    }
    return name;
}

void asn1_resource::for_each_type_name(std::function<void(asn1_entity_t, const std::string&)> f) const {
    if (f) {
        for (auto item : _type_id) {
            f(item.first, item.second);
        }
    }
}

}  // namespace io
}  // namespace hotplace
