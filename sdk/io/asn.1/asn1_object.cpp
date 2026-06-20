/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_object.cpp
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
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/asn.1/asn1_container.hpp>
#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/asn1_visitor.hpp>

namespace hotplace {
namespace io {

asn1_object::asn1_object(asn1_entity_t entity, const std::string& name, asn1_object* object, asn1_tag* tag)
    : _ident(0), _name(name), _entity(entity), _component_entity(entity), _component_type(0), _suppress(false), _parent(nullptr), _tag(tag), _object(object) {
    _shared.make_share(this);
    if (tag) tag->set_parent(this);
    if (object) object->set_parent(this);
}

asn1_object::asn1_object(const asn1_object& other) : asn1_object(asn1_entity_syntax, "", nullptr, nullptr) { *this = other; }

asn1_object::asn1_object(asn1_object&& other) : asn1_object(asn1_entity_syntax, "", nullptr, nullptr) { *this = std::move(other); }

asn1_object::~asn1_object() {}

asn1_object& asn1_object::operator=(const asn1_object& other) {
    _ident = other._ident;
    _name = other._name;
    _entity = other._entity;
    _component_entity = other._component_entity;
    _component_type = other._component_type;
    _suppress = other._suppress;
    _parent = other._parent;
    if (other._tag) {
        _tag = other._tag->clone();
        _tag->set_parent(this);
    }
    if (other._object) {
        _object = other._object->clone();
        _object->set_parent(this);
    }
    return *this;
}

asn1_object& asn1_object::operator=(asn1_object&& other) {
    std::swap(_ident, other._ident);
    std::swap(_name, other._name);
    std::swap(_entity, other._entity);
    std::swap(_component_entity, other._component_entity);
    std::swap(_component_type, other._component_type);
    std::swap(_suppress, other._suppress);
    std::swap(_parent, other._parent);
    std::swap(_tag, other._tag);
    std::swap(_object, other._object);
    return *this;
}

asn1_object* asn1_object::clone() { return new asn1_object(*this); }

asn1_value* asn1_object::instantiate() { return new asn1_value(this); }

asn1_object* asn1_object::addref() {
    if (_tag) _tag->addref();
    if (_object) _object->addref();
    _shared.addref();
    return this;
}

void asn1_object::release() {
    if (_tag) _tag->release();
    if (_object) _object->release();
    _shared.delref();
}

void asn1_object::publish(binary_t* b) {
    asn1_der_visitor encoder(b);
    accept(&encoder);
}

void asn1_object::publish(stream_t* s) {
    asn1_notation_visitor notation(s);
    accept(&notation);
}

asn1_object& asn1_object::set_name(const std::string& name) {
    _name = name;
    return *this;
}

asn1_object& asn1_object::set_parent(asn1_object* parent) {
    _parent = parent;
    return *this;
}

uint8 asn1_object::get_ident() const { return _ident; }

asn1_object* asn1_object::get_parent() const { return _parent; }

asn1_object* asn1_object::get_object() const { return _object; }

const std::string& asn1_object::get_name() const { return _name; }

asn1_object& asn1_object::set_entity(asn1_entity_t entity) {
    _entity = entity;
    return *this;
}

asn1_object& asn1_object::set_component_entity(asn1_entity_t entity) {
    _component_entity = entity;
    return *this;
}

asn1_entity_t asn1_object::get_entity() const { return _entity; }

asn1_entity_t asn1_object::get_component_entity() const { return _component_entity; }

asn1_tag* asn1_object::get_tag() const { return _tag; }

int asn1_object::get_componenttype() { return _component_type; }

asn1_object& asn1_object::as_default() {
    _component_type = asn1_default;
    return *this;
}

asn1_object& asn1_object::as_optional() {
    _component_type = asn1_optional;
    return *this;
}

asn1_object& asn1_object::as_primitive() {
    _ident &= ~asn1_tag_constructed;
    if (_object) {
        _object->_ident = _ident;
    }
    return *this;
}

asn1_object& asn1_object::as_constructed() {
    _ident |= asn1_tag_constructed;
    if (_object) {
        _object->_ident = _ident;
    }
    return *this;
}

bool asn1_object::is_named_type() const { return _name.empty() ? false : true; }

bool asn1_object::is_primitive() const { return (_ident & asn1_tag_mask) ? false : true; }

bool asn1_object::is_constructed() const { return (_ident & asn1_tag_mask) ? true : false; }

bool asn1_object::is_tagged() const { return _tag ? true : false; }

void asn1_object::accept(asn1_visitor* v) { v->visit(this); }

void asn1_object::represent(uint32 depth, stream_t* s, asn1_value* value) {}

bool asn1_object::represent(uint32 depth, binary_t* b, asn1_value* value, uint16 flags) { return true; }

asn1_object& asn1_object::suppress() {
    _suppress = true;
    if (_tag) _tag->suppress();
    if (_object) _object->suppress();
    return *this;
}

asn1_object& asn1_object::unsuppress() {
    _suppress = false;
    if (_tag) _tag->unsuppress();
    if (_object) _object->unsuppress();
    return *this;
}

bool asn1_object::is_suppressed() { return _suppress; }

}  // namespace io
}  // namespace hotplace
