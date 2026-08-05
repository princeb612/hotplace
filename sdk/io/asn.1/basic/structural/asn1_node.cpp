/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_node.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/io/asn.1/basic/structural/asn1_node.hpp>

namespace hotplace {
namespace io {

asn1_node::asn1_node(uint8 identifier, uint64 tag, uint64 len) : _parent(nullptr), _identifier(identifier), _tag(tag), _len(len) { _shared.make_share(this); }

asn1_node::asn1_node(const asn1_node& other) { *this = other; }

asn1_node::~asn1_node() { clear(); }

asn1_node& asn1_node::operator=(const asn1_node& other) {
    clear();
    _identifier = other._identifier;
    _tag = other._tag;
    _len = other._len;
    _children = other._children;
    return *this;
}

asn1_node* asn1_node::clone() { return new asn1_node(*this); }

asn1_node& asn1_node::add(asn1_node* child) {
    if (child) {
        if (is_container()) {
            _children.push_back(child);
            child->set_parent(this);
        } else {
            child->release();
            throw exception(errorcode_t::not_available);
        }
    }
    return *this;
}

asn1_node& asn1_node::operator<<(asn1_node* child) { return add(child); }

void asn1_node::clear() {
    for (auto& child : _children) {
        child->release();
    }
    _children.clear();
}

void asn1_node::for_each(std::function<void(asn1_node*)> f) const {
    if (f) {
        for (auto& child : _children) f(child);
    }
}

size_t asn1_node::size() const { return _children.size(); }

bool asn1_node::is_leaf() const { return _children.empty(); }

void asn1_node::set_parent(asn1_node* parent) { _parent = parent; }

asn1_node* asn1_node::get_parent() { return _parent; }

void asn1_node::set_name(const std::string& name) { _name = name; }

const std::string& asn1_node::get_name() const { return _name; }

uint8 asn1_node::get_identifier() const { return _identifier; }

uint64 asn1_node::get_tag() const { return _tag; }

uint64 asn1_node::get_len() const { return _len; }

bool asn1_node::is_container() { return true; }

void asn1_node::addref() { _shared.addref(); }

void asn1_node::release() { _shared.delref(); }

}  // namespace io
}  // namespace hotplace
