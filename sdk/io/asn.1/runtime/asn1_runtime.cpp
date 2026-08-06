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

#include <hotplace/sdk/base/encoding/base128.hpp>
#include <hotplace/sdk/base/encoding/base16.hpp>
#include <hotplace/sdk/base/nostd/atoi.hpp>
#include <hotplace/sdk/base/stream/vtprintf.hpp>
#include <hotplace/sdk/base/system/ieee754.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_builder.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_any.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_builtin_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_container.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tagged_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/builtin/asn1_bitstring.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/builtin/asn1_integer.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_der_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_notation_visitor.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_weakly_typed.hpp>
#include <hotplace/sdk/io/basic/oid.hpp>

namespace hotplace {
namespace io {

asn1_runtime::asn1_runtime() {
    _shared.make_share(this);
    // get_parser().get_config().set("handle_quot_as_unquoted", 1);
    // get_parser().add_token("::=", token_assign).add_token("--", token_comments);
}

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

asn1_runtime& asn1_runtime::add(asn1_object* item) {
    if (item) {
        _types.push_back(item);
        const std::string& name = item->get_name();
        if (false == name.empty()) {
            _dictionary.emplace(name, item);
        }
    }
    return *this;
}

asn1_runtime& asn1_runtime::add(asn1_object* item, std::function<void(asn1_object*)> f) {
    if (item && f) {
        f(item);
        add(item);
    }
    return *this;
}

asn1_runtime& asn1_runtime::operator<<(asn1_object* item) { return add(item); }

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

return_t asn1_runtime::read(const byte_t* stream, size_t size, size_t& pos) {
    asn1_weakly_typed awt;
    auto test = awt.read(this, stream, size, pos);
    if (errorcode_t::success != test) return test;

    return errorcode_t::success;
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
        item->accept(&notation);
        if (nl) s->printf("\n");
    }
}

void asn1_runtime::publish(stream_t* s) {
    auto nl = _types.size() > 1;
    for (const auto& pair : _values) {
        auto value = pair.second;
        asn1_notation_visitor notation(s, value);
        value->get_schema()->accept(&notation);
        if (nl) s->printf("\n");
    }
}

void asn1_runtime::publish(binary_t* b) {
    for (const auto& pair : _values) {
        auto value = pair.second;
        asn1_der_visitor encoder(b, value);
        value->get_schema()->accept(&encoder);
    }
}

void asn1_runtime::clear() {
    for (auto item : _types) item->release();
    for (auto& pair : _values) pair.second->release();
    _types.clear();
    _values.clear();
}

void asn1_runtime::addref() { _shared.addref(); }

void asn1_runtime::release() { _shared.delref(); }

// parser& asn1_runtime::get_parser() { return _parser; }
//
// const parser::context& asn1_runtime::get_rule_context() const { return _rule; }

}  // namespace io
}  // namespace hotplace
