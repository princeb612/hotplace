/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1.cpp
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
#include <hotplace/sdk/io/asn.1/basic/asn1.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_any.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_builder.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_builtin_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_container.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_der_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_notation_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_tagged_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_weak_typed.hpp>
#include <hotplace/sdk/io/asn.1/basic/builtin/asn1_bitstring.hpp>
#include <hotplace/sdk/io/asn.1/basic/builtin/asn1_integer.hpp>
#include <hotplace/sdk/io/basic/oid.hpp>

namespace hotplace {
namespace io {

asn1::asn1() {
    _shared.make_share(this);
    // get_parser().get_config().set("handle_quot_as_unquoted", 1);
    // get_parser().add_token("::=", token_assign).add_token("--", token_comments);
}

asn1::asn1(const asn1& other) : asn1() {
    for (auto item : other._types) {
        add(item->clone());
    }
}

asn1::~asn1() { clear(); }

asn1& asn1::operator=(const asn1& other) {
    for (auto item : other._types) {
        add(item->clone());
    }
    return *this;
}

asn1* asn1::clone() { return new asn1(*this); }

asn1& asn1::add(asn1_object* item) {
    if (item) {
        _types.push_back(item);
        const std::string& name = item->get_name();
        if (false == name.empty()) {
            _dictionary.emplace(name, item);
        }
    }
    return *this;
}

asn1& asn1::add(asn1_object* item, std::function<void(asn1_object*)> f) {
    if (item && f) {
        f(item);
        add(item);
    }
    return *this;
}

asn1& asn1::operator<<(asn1_object* item) { return add(item); }

return_t asn1::read(const byte_t* stream, size_t size, size_t& pos) {
    asn1_weak_typed awt;
    auto test = awt.read(this, stream, size, pos);
    if (errorcode_t::success != test) return test;

    return errorcode_t::success;
}

void asn1::for_each(std::function<void(asn1_object*)> f) const {
    for (const auto& item : _types) {
        f(item);
    }
}

void asn1::for_each(std::function<void(asn1_value*)> f) const {
    for (const auto& item : _values) {
        f(item);
    }
}

void asn1::notation(stream_t* s) {
    asn1_notation_visitor notation(s);
    auto nl = _types.size() > 1;
    for (auto item : _types) {
        item->accept(&notation);
        if (nl) s->printf("\n");
    }
}

void asn1::publish(stream_t* s) {
    auto nl = _types.size() > 1;
    for (auto item : _values) {
        asn1_notation_visitor notation(s, item);
        item->get_schema()->accept(&notation);
        if (nl) s->printf("\n");
    }
}

void asn1::publish(binary_t* b) {
    for (auto item : _values) {
        asn1_der_visitor encoder(b, item);
        item->get_schema()->accept(&encoder);
    }
}

void asn1::clear() {
    for (auto item : _types) item->release();
    for (auto item : _values) item->release();
    _types.clear();
    _values.clear();
}

void asn1::addref() { _shared.addref(); }

void asn1::release() { _shared.delref(); }

// parser& asn1::get_parser() { return _parser; }
//
// const parser::context& asn1::get_rule_context() const { return _rule; }

}  // namespace io
}  // namespace hotplace
