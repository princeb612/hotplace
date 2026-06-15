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

#include <hotplace/sdk/io/asn.1/asn1.hpp>
#include <hotplace/sdk/io/asn.1/asn1_container.hpp>
#include <hotplace/sdk/io/asn.1/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/asn1_visitor.hpp>

namespace hotplace {
namespace io {

asn1::asn1() {
    _shared.make_share(this);
    // get_parser().get_config().set("handle_quot_as_unquoted", 1);
    // get_parser().add_token("::=", token_assign).add_token("--", token_comments);
}

asn1::asn1(const asn1& other) {
    _shared.make_share(this);
    for (auto item : other._types) {
        add(item->clone());
    }
}

asn1& asn1::operator=(const asn1& other) {
    for (auto item : other._types) {
        add(item->clone());
    }
    return *this;
}

asn1* asn1::clone() { return new asn1(*this); }

asn1::~asn1() { clear(); }

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

asn1& asn1::operator<<(asn1_object* item) { return add(item); }

void asn1::publish(binary_t* b) {
    asn1_der_visitor encoder(b);
    for (auto item : _types) {
        item->accept(&encoder);
    }
}

void asn1::publish(stream_t* s) {
    asn1_notation_visitor notation(s);
    auto nl = _types.size() > 1;
    for (auto item : _types) {
        item->accept(&notation);
        if (nl) s->printf("\n");
    }
}

void asn1::clear() {
    for (auto item : _types) {
        item->release();
    }
    _types.clear();
    _dictionary.clear();
    _namevalues.clear();
    _idxvalues.clear();
}

void asn1::addref() { _shared.addref(); }

void asn1::release() { _shared.delref(); }

// parser& asn1::get_parser() { return _parser; }
//
// const parser::context& asn1::get_rule_context() const { return _rule; }

}  // namespace io
}  // namespace hotplace
