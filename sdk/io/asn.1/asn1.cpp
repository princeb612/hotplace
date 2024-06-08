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

asn1::asn1() {
    get_parser().get_config().set("handle_quot_as_unquoted", 1);
    get_parser().add_token("::=", token_assign).add_token("--", token_comments);
}

asn1::~asn1() { clear(); }

asn1& asn1::add_rule(const char* rule) {
    _buf << rule << "\n";  // rules
    return *this;
}

asn1& asn1::learn() {
    _parser.parse(_rule, _buf.c_str(), _buf.size());  // rules
    return *this;
}

asn1& asn1::operator<<(asn1_object* rhs) {
    if (rhs) {
        _list.push_back(rhs);
        const std::string& name = rhs->get_name();
        if (false == name.empty()) {
            _dictionary.insert({name, rhs});
        }
    }
    return *this;
}

asn1_object* asn1::clone(const std::string& name) {
    asn1_object* object = nullptr;
    auto iter = _dictionary.find(name);
    if (_dictionary.end() != iter) {
        object = iter->second;
        object->addref();
    }
    return object;
}

void asn1::publish(binary_t* b) {
    asn1_encoder encoder(b);
    for (auto item : _list) {
        item->accept(&encoder);
    }
}

void asn1::publish(stream_t* s) {
    asn1_notation notation(s);
    for (auto item : _list) {
        item->accept(&notation);
        s->printf("\n");
    }
}

void asn1::clear() {
    for (auto item : _list) {
        item->release();
    }
}

parser& asn1::get_parser() { return _parser; }

const parser::context& asn1::get_rule_context() const { return _rule; }

}  // namespace io
}  // namespace hotplace
