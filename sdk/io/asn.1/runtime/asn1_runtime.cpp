/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_runtime.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_referenced_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tagged_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_der_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_notation_visitor.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_strongly_typed.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_weakly_typed.hpp>

namespace hotplace {
namespace io {

asn1_runtime::asn1_runtime() {
    _shared.make_share(this);
    // get_parser().get_config().set("handle_quot_as_unquoted", 1);
    // get_parser().add_token("::=", token_assign).add_token("--", token_comments);
    _automatic = asn1_explicit;
}

asn1_runtime::asn1_runtime(const std::string& name) : asn1_runtime() { _name = name; }

asn1_runtime::asn1_runtime(const asn1_runtime& other) : asn1_runtime() { *this = other; }

asn1_runtime::~asn1_runtime() { clear(); }

asn1_runtime& asn1_runtime::operator=(const asn1_runtime& other) {
    for (auto item : other._types) {
        auto type = item->clone();

        add(type);

        auto value = other.get(item);
        if (value) {
            _values.emplace(type, new asn1_value(*value));
        }
    }
    return *this;
}

asn1_runtime* asn1_runtime::clone() { return new asn1_runtime(*this); }

return_t asn1_runtime::add(asn1_object* item) {
    if (nullptr == item) return errorcode_t::invalid_parameter;

    _types.push_back(item);
    const std::string& name = item->get_name();
    if (false == name.empty()) {
        _dictionary.emplace(name, item);
    }

    return errorcode_t::success;
}

asn1_runtime& asn1_runtime::add(asn1_object* item, std::function<void(asn1_object*)> f) {
    if (item && f) {
        f(item);
        add(item);
    }
    return *this;
}

asn1_runtime& asn1_runtime::operator<<(asn1_object* item) {
    add(item);
    return *this;
}

return_t asn1_runtime::add_schema(const std::string& schema, asn1_object* item) {
    if (nullptr == item) return errorcode_t::invalid_parameter;
    auto pib = _schema.emplace(item, schema);
    if (false == pib.second) return errorcode_t::already_exist;
    return add(item);
}

return_t asn1_runtime::set(asn1_object* item, asn1_value* value) {
    return_t ret = errorcode_t::success;
    if (item && value) {
        auto pib = _values.emplace(item, value);
        if (false == pib.second) {
            ret = errorcode_t::already_exist;
        }
    } else
        ret = errorcode_t::invalid_parameter;
    return ret;
}

asn1_object* asn1_runtime::get(const std::string& name) const {
    asn1_object* ret_value = nullptr;
    if (name.empty() && (1 == _types.size())) {
        ret_value = *_types.begin();
    } else {
        auto iter = _dictionary.find(name);
        if (_dictionary.end() != iter) {
            ret_value = iter->second;
        }
    }
    return ret_value;
}

asn1_value* asn1_runtime::get(asn1_object* item) const {
    asn1_value* ret_value = nullptr;
    if (item) {
        auto iter = _values.find(item);
        if (_values.end() != iter) {
            ret_value = iter->second;
        }
    }
    return ret_value;
}

return_t asn1_runtime::read_weakly_typed(const byte_t* stream, size_t size, size_t& pos) {
    asn1_weakly_typed weaktype;
    return weaktype.read(this, stream, size, pos);
}

return_t asn1_runtime::read(const std::string& name, const byte_t* stream, size_t size, size_t& pos) {
    asn1_strongly_typed strongtype;
    return strongtype.read(this, name, stream, size, pos);
}

void asn1_runtime::update_linkage(asn1_object* object) {
    if (nullptr == object) return;

    auto entity = object->get_entity();
    switch (entity) {
        case asn1_entity_tagged_type: {
            auto tagtype = (asn1_tagged_type*)object;
            tagtype->update_linkage();
        } break;
        case asn1_entity_referenced_type: {
            auto ref = (asn1_referenced_type*)object;
            if (ref->is_reference()) {
                if (nullptr == ref->get_object()) {
                    auto schema = get(ref->get_reference());
                    if (nullptr == schema) throw exception(errorcode_t::not_found);
                    auto clone = schema->clone();
                    ref->set_object(clone);
                }
                auto parent = object->get_parent();  // asn1_entity_tagged_type
                if (parent)
                    update_linkage(parent);
                else
                    update_linkage(ref->get_object());
            }
        } break;
        default: {
        } break;
    }
}

void asn1_runtime::for_each(std::function<void(asn1_object*)> f) const {
    for (const auto& item : _types) {
        f(item);
    }
}

void asn1_runtime::for_each(std::function<void(asn1_value*)> f) const {
    for (const auto& pair : _values) {
        f(pair.second);
    }
}

void asn1_runtime::notation(stream_t* s) {
    asn1_notation_visitor notation(s);
    auto nl = _types.size() > 1;
    for (auto item : _types) {
        notation.visit(item);
        if (nl) s->printf("\n");
    }
}

void asn1_runtime::publish(stream_t* s) {
    auto nl = _types.size() > 1;
    for (const auto& pair : _values) {
        auto value = pair.second;
        asn1_notation_visitor notation(s, value);
        notation.visit(value->get_schema());
        if (nl) s->printf("\n");
    }
}

void asn1_runtime::publish(binary_t* b) {
    for (const auto& pair : _values) {
        auto value = pair.second;
        asn1_der_visitor encoder(b, this, value);
        encoder.visit(value->get_schema());
    }
}

void asn1_runtime::notation(const std::string& name, stream_t* s) {
    auto schema = get(name);
    if (nullptr == schema) return;

    asn1_notation_visitor notation(s);
    notation.visit(schema);
}

void asn1_runtime::publish(const std::string& name, stream_t* s) {
    auto schema = get(name);
    if (nullptr == schema) return;

    auto value = get(schema);
    if (nullptr == value) return;

    asn1_notation_visitor notation(s, value);
    notation.visit(value->get_schema());
}

void asn1_runtime::publish(const std::string& name, binary_t* b) {
    auto schema = get(name);
    if (nullptr == schema) return;

    auto value = get(schema);
    if (nullptr == value) return;

    asn1_der_visitor encoder(b, this, value);
    encoder.visit(schema);
}

void asn1_runtime::set_name(const std::string& name) { _name = name; }

std::string asn1_runtime::get_name() { return _name; }

void asn1_runtime::set_automatic(uint8 runas) { _automatic = runas; }

uint8 asn1_runtime::runas_automatic() { return _automatic; }

void asn1_runtime::clear() {
    for (auto item : _types) item->release();
    for (auto& pair : _values) pair.second->release();
    _types.clear();
    _values.clear();
    _schema.clear();
}

void asn1_runtime::addref() { _shared.addref(); }

void asn1_runtime::release() { _shared.delref(); }

// parser& asn1_runtime::get_parser() { return _parser; }
//
// const parser::context& asn1_runtime::get_rule_context() const { return _rule; }

}  // namespace io
}  // namespace hotplace
