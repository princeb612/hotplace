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
#include <sdk/io/asn.1/asn1_object.hpp>
#include <sdk/io/asn.1/asn1_visitor.hpp>

namespace hotplace {
namespace io {

asn1::asn1() {
    _ref.make_share(this);
    // get_parser().get_config().set("handle_quot_as_unquoted", 1);
    // get_parser().add_token("::=", token_assign).add_token("--", token_comments);
}

asn1::asn1(const asn1& rhs) {
    _ref.make_share(this);
    for (auto item : rhs._types) {
        add_type(item->clone());
    }
}

asn1* asn1::clone() { return new asn1(*this); }

asn1::~asn1() { clear(); }

asn1& asn1::add_type(asn1_object* item) {
    if (item) {
        _types.push_back(item);
        const std::string& name = item->get_name();
        if (false == name.empty()) {
            _dictionary.insert({name, item});
        }
    }
    return *this;
}

asn1& asn1::operator<<(asn1_object* item) { return add_type(item); }

asn1& asn1::set_value_byname(const std::string& name, const variant& value) {
    auto iter = _dictionary.find(name);
    if (_dictionary.end() != iter) {
        auto item = iter->second;
        item->get_data() = value;
    }
    return *this;
}

asn1& asn1::set_value_byname(const std::string& name, variant&& value) {
    auto iter = _dictionary.find(name);
    if (_dictionary.end() != iter) {
        auto item = iter->second;
        item->get_data() = std::move(value);
    }
    return *this;
}

asn1& asn1::set_value_byindex(unsigned index, const variant& value) {
    if (index < _types.size()) {
        auto iter = _types.begin();
        std::advance(iter, index);
        (*iter)->get_data() = value;
    }
    return *this;
}

asn1& asn1::set_value_byindex(unsigned index, variant&& value) {
    if (index < _types.size()) {
        auto iter = _types.begin();
        std::advance(iter, index);
        (*iter)->get_data() = std::move(value);
    }
    return *this;
}

asn1_object* asn1::operator[](const std::string& name) {
    asn1_object* item = nullptr;
    auto iter = _dictionary.find(name);
    if (_dictionary.end() != iter) {
        item = iter->second;
    }
    return item;
}
asn1_object* asn1::operator[](unsigned index) {
    asn1_object* item = nullptr;
    if (index < _types.size()) {
        auto iter = _types.begin();
        std::advance(iter, index);
        item = *iter;
    }
    return item;
}

void asn1::publish(binary_t* b) {
    asn1_basic_encoding_visitor encoder(b);
    for (auto item : _types) {
        item->accept(&encoder);
    }
}

void asn1::publish(stream_t* s) {
    asn1_notation_visitor notation(s);
    for (auto item : _types) {
        item->accept(&notation);
        s->printf("\n");
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

void asn1::addref() { _ref.addref(); }

void asn1::release() { _ref.delref(); }

// parser& asn1::get_parser() { return _parser; }
//
// const parser::context& asn1::get_rule_context() const { return _rule; }

}  // namespace io
}  // namespace hotplace
