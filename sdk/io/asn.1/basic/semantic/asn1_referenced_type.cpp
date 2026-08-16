/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_referenced_type.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

// #include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
// #include <hotplace/sdk/base/system/trace.hpp>
// #include <hotplace/sdk/io/asn.1/basic/asn1_encode.hpp>
// #include <hotplace/sdk/io/asn.1/basic/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_builtin_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_referenced_type.hpp>
// #include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tag.hpp>
// #include <hotplace/sdk/io/asn.1/runtime/asn1_runtime.hpp>

namespace hotplace {
namespace io {

asn1_referenced_type::asn1_referenced_type(const std::string& name) : asn1_type(asn1_entity_referenced_type, name, nullptr, nullptr) {}

asn1_referenced_type::asn1_referenced_type(const std::string& name, asn1_object* object) : asn1_type(asn1_entity_referenced_type, name, object, nullptr) {}

asn1_referenced_type::asn1_referenced_type(const std::string& name, const std::string& reference) : asn1_type(asn1_entity_referenced_type, name, nullptr, nullptr) {
    _reference = reference;
}

asn1_referenced_type::asn1_referenced_type(const asn1_referenced_type& other) : asn1_type(asn1_entity_referenced_type) { *this = other; }

asn1_referenced_type::~asn1_referenced_type() {}

asn1_referenced_type* asn1_referenced_type::clone() { return new asn1_referenced_type(*this); }

asn1_referenced_type& asn1_referenced_type::operator=(const asn1_referenced_type& other) {
    asn1_object::operator=(other);
    _reference = other._reference;
    return *this;
}

asn1_referenced_type* asn1_referenced_type::define(const std::string& name, asn1_entity_t entity) {
    return new asn1_referenced_type(name, new asn1_builtin_type(entity));
}

asn1_referenced_type* asn1_referenced_type::define(const std::string& name, asn1_object* object) { return new asn1_referenced_type(name, object); }

asn1_referenced_type* asn1_referenced_type::refer(const std::string& name, const std::string& reference) { return new asn1_referenced_type(name, reference); }

asn1_referenced_type* asn1_referenced_type::refer(const std::string& reference) { return new asn1_referenced_type("", reference); }

bool asn1_referenced_type::is_reference() const { return get_object() ? false : true; }

bool asn1_referenced_type::is_definition() const { return get_object() ? true : false; }

const std::string& asn1_referenced_type::get_reference() const { return _reference; }

void asn1_referenced_type::represent(stream_t* s, const asn1_value* value) const {
    s->printf("%s", get_name().c_str());

    if (is_definition()) {
        if (nullptr == get_parent()) {
            auto obj = get_object();
            s->printf(" ::= ");
            obj->represent(s, value);
        }
    } else if (false == _reference.empty()) {
        if (false == get_name().empty()) s->printf(" ");
        s->printf("%s", _reference.c_str());
    }
}

bool asn1_referenced_type::represent(binary_t* b, const asn1_value* value, uint16 flags) const {
    auto obj = get_object();
    if (obj) {
        /**
         * if (is_definition())
         *     get_object()->represent(...);
         * if (is_reference()) {
         *     schema = runtime->get(get_reference());
         *     if (schema) schema->represent(...);
         *     else error
         * }
         */
        obj->represent(b, value);
    }

    return true;
}

}  // namespace io
}  // namespace hotplace
