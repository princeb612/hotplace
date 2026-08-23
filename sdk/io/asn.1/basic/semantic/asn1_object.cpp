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

#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_container.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_der_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_notation_visitor.hpp>

namespace hotplace {
namespace io {

asn1_object::asn1_object(asn1_entity_t entity, const std::string& name, asn1_object* object, asn1_tag* tag)
    : _ident(0), _name(name), _entity(entity), _component_type(0), _suppress(false), _parent(nullptr), _tag(nullptr), _object(nullptr), _default(nullptr) {
    _shared.make_share(this);
    set_object(object);
    set_tag(tag);
}

asn1_object::asn1_object(const asn1_object& other) : asn1_object(asn1_entity_syntax, "", nullptr, nullptr) { *this = other; }

asn1_object::~asn1_object() {
    if (_default) delete _default;
}

asn1_object& asn1_object::operator=(const asn1_object& other) {
    _ident = other._ident;
    _name = other._name;
    _entity = other._entity;
    _component_type = other._component_type;
    _suppress = other._suppress;
    _parent = other._parent;
    set_object(other._object ? other._object->clone() : nullptr);
    set_tag(other._tag ? other._tag->clone() : nullptr);
    if (other._default) set_default_value(other._default->vt);
    _constraints = other._constraints;
    return *this;
}

asn1_object* asn1_object::clone() { return new asn1_object(*this); }

asn1_value* asn1_object::instantiate() { return new asn1_value(this); }

asn1_object* asn1_object::addref() {
    if (_tag) _tag->addref();
    if (_object) _object->addref();
    get_constraints().addref();
    _shared.addref();
    return this;
}

void asn1_object::release() {
    if (_tag) _tag->release();
    if (_object) _object->release();
    get_constraints().release();
    _shared.delref();
}

void asn1_object::publish(binary_t* b) {
    asn1_der_visitor encoder(b, nullptr);
    encoder.visit(this);
}

void asn1_object::publish(stream_t* s) {
    asn1_notation_visitor notation(s);
    notation.visit(this);
}

asn1_object& asn1_object::set_name(const std::string& name) {
    _name = name;
    return *this;
}

void asn1_object::set_parent(asn1_object* parent) { _parent = parent; }

uint8 asn1_object::get_ident() const { return _ident; }

asn1_object* asn1_object::get_parent() const { return _parent; }

asn1_object* asn1_object::get_object() const { return _object; }

const std::string& asn1_object::get_name() const { return _name; }

asn1_object& asn1_object::set_entity(asn1_entity_t entity) {
    _entity = entity;
    return *this;
}

asn1_object& asn1_object::set_default_value(const variant_t& value) {
    if (_default) delete _default;
    _default = new asn1_default_t(value);
    _component_type = asn1_default;
    return *this;
}

asn1_object& asn1_object::set_default_value(variant_t&& value) {
    if (_default) delete _default;
    _default = new asn1_default_t(std::move(value));
    _component_type = asn1_default;
    return *this;
}

void asn1_object::set_tag(asn1_tag* tag) {
    if (_tag) _tag->release();
    _tag = tag;
    if (tag) tag->set_parent(this);
}

void asn1_object::set_object(asn1_object* object) {
    if (_object) _object->release();
    _object = object;
    if (object) object->set_parent(this);
}

asn1_entity_t asn1_object::get_entity() const { return _entity; }

asn1_entity_t asn1_object::get_component_entity() const { return _entity; }

uint16 asn1_object::get_component_type() const { return _component_type; }

asn1_tag* asn1_object::get_tag() const { return _tag; }

variant_t asn1_object::get_default_value() const {
    variant_t vt;
    if (_default) vt = _default->vt;
    return vt;
}

std::string asn1_object::resolve_name() const {
    std::string name;

    auto lambda_join = [](const std::vector<std::string>& path, const std::string& word) -> std::string {
        std::string value;
        for (auto iter = path.begin(); iter != path.end(); ++iter) {
            if (iter != path.begin()) {
                value += word;
            }
            value += *iter;
        }
        return value;
    };

    const asn1_object* node = this;
    std::vector<std::string> path;
    while (node) {
        auto entity = node->get_component_entity();
        switch (entity) {
            case asn1_entity_builtin_type:
            case asn1_entity_tagged_type:
            case asn1_entity_sequence:
            case asn1_entity_sequence_of:
            case asn1_entity_set:
            case asn1_entity_set_of:
            case asn1_entity_choice:
            case asn1_entity_enum:
            case asn1_entity_any: {
                const auto& nodename = node->get_name();
                if (false == nodename.empty()) {
                    path.push_back(nodename);
                }
            } break;
            case asn1_entity_referenced_type:
            default:
                break;
        }

        node = node->get_parent();  // transparent
    };

    std::reverse(path.begin(), path.end());
    name = lambda_join(path, ".");

    return name;
}

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
    return *this;
}

asn1_object& asn1_object::as_constructed() {
    _ident |= asn1_tag_constructed;
    return *this;
}

bool asn1_object::is_named_type() const { return _name.empty() ? false : true; }

bool asn1_object::is_primitive() const { return (_ident & asn1_tag_mask) ? false : true; }

bool asn1_object::is_constructed() const { return (_ident & asn1_tag_mask) ? true : false; }

bool asn1_object::is_tagged() const { return _tag ? true : false; }

bool asn1_object::is_default() const { return asn1_default == _component_type; }

void asn1_object::suppress() {
    _suppress = true;
    if (_tag) _tag->suppress();
    if (_object) _object->suppress();
}

void asn1_object::unsuppress() {
    _suppress = false;
    if (_tag) _tag->unsuppress();
    if (_object) _object->unsuppress();
}

bool asn1_object::is_suppressed() const { return _suppress; }

void asn1_object::represent(stream_t* s, const asn1_value* value) const {}

bool asn1_object::represent(binary_t* b, const asn1_value* value, uint16 flags) const { return true; }

asn1_constraints& asn1_object::get_constraints() { return _constraints; }

const asn1_constraints& asn1_object::get_constraints() const { return _constraints; }

bool asn1_object::have_constraints() const { return false == get_constraints().empty(); }

bool asn1_object::validate(const asn1_value* value) {
    if (nullptr == value || nullptr == value) return false;

    return validate_node(this, value);
}

bool asn1_object::validate_node(const asn1_object* node, const asn1_value* value) {
    if (nullptr == value) return false;

    while (node) {
        if (node->have_constraints()) {
            // (false == get_constraints.empty()) || (asn1_enum return true)
            return node->get_constraints().validate(node, value);
        }
        if (is_kind_of_container(node)) {
            auto container = dynamic_cast<const asn1_container*>(node);
            auto test = container->for_each([&](asn1_object* item) -> bool { return item->validate_node(item, value); });
            if (false == test) return false;
        }
        node = node->get_object();
    }
    return true;
}

void asn1_object::update_linkage() {}

}  // namespace io
}  // namespace hotplace
