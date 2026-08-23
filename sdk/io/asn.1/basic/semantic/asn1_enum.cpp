/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_enum.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_enum.hpp>

namespace hotplace {
namespace io {

asn1_enum::asn1_enum() : asn1_enum("") {}

asn1_enum::asn1_enum(const std::string& name) : asn1_type(asn1_entity_enum, name, nullptr) { as_primitive(); }

asn1_enum::asn1_enum(const std::initializer_list<std::pair<std::string, asn1_native_int_t>>& items) : asn1_enum("", items) {}

asn1_enum::asn1_enum(const std::string& name, const std::initializer_list<std::pair<std::string, asn1_native_int_t>>& items)
    : asn1_type(asn1_entity_enum, name, nullptr) {
    as_primitive();
    add(items);
}

asn1_enum::~asn1_enum() {}

asn1_enum* asn1_enum::clone() { return new asn1_enum(*this); }

asn1_enum* asn1_enum::addref() {
    asn1_type::addref();
    return this;
}

asn1_entity_t asn1_enum::get_component_entity() const { return asn1_entity_enum; }

asn1_enum& asn1_enum::add(const std::string& en, asn1_native_int_t value) {
    _enum.emplace(en, value);
    _reverse.emplace(value, en);
    return *this;
}

bool asn1_enum::have_constraints() const { return true; }

bool asn1_enum::evaluate(const std::string& name) const { return _enum.count(name) > 0; }

asn1_enum& asn1_enum::operator<<(const std::initializer_list<std::pair<std::string, asn1_native_int_t>>& items) { return add(items); }

asn1_enum& asn1_enum::add(const std::initializer_list<std::pair<std::string, asn1_native_int_t>>& items) {
    for (const auto& item : items) {
        add(item.first, item.second);
    }
    return *this;
}

void asn1_enum::represent(stream_t* s, const asn1_value* value) const {
    auto resource = asn1_resource::get_instance();
    auto entity = get_entity();

    if (false == get_name().empty()) s->printf("%s ", get_name().c_str());

    s->printf("%s ", resource->get_entity_name(get_ident(), entity).c_str());
    s->printf("{");
    if (false == _reverse.empty()) {
        auto iter = _reverse.begin();
        s->printf("%s(%i)", iter->second.c_str(), iter->first);
        ++iter;
        while (_reverse.end() != iter) {
            s->printf(", %s(%i)", iter->second.c_str(), iter->first);
            ++iter;
        }
    }
    s->printf("}");
}

bool asn1_enum::represent(binary_t* b, const asn1_value* value, uint16 flags) const {
    if (value) {
        auto name = resolve_name();
        auto snapshot = b->size();

        asn1_encode::write_identifier2(*b, this);
        auto pos = b->size();
        auto test = value->encode_namedlist(*b, this, name, _enum);
        asn1_encode::write_length(*b, b->size() - pos, pos);

        if (false == test) {
            b->resize(snapshot);  // rollback
        }
    }

    return true;
}

}  // namespace io
}  // namespace hotplace
