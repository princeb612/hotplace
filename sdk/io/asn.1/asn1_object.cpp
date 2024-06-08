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

asn1_object::asn1_object(asn1_type_t type, asn1_tagged* tag) : _type(type), _tag(tag), _component_type(0) { _ref.make_share(this); }

asn1_object::asn1_object(const std::string& name, asn1_type_t type, asn1_tagged* tag) : _name(name), _type(type), _tag(tag), _component_type(0) {
    _ref.make_share(this);
}

const std::string& asn1_object::get_name() const { return _name; }

asn1_type_t asn1_object::get_type() const { return _type; }

asn1_tagged* asn1_object::get_tag() { return _tag; }

int asn1_object::get_componenttype() { return _component_type; }

asn1_object& asn1_object::set_default() {
    _component_type = asn1_default;
    return *this;
}

asn1_object& asn1_object::set_optional() {
    _component_type = asn1_optional;
    return *this;
}

variant& asn1_object::get_data() { return _var; }

const variant& asn1_object::get_data() const { return _var; }

void asn1_object::accept(asn1_visitor* v) { v->visit(this); }

void asn1_object::represent(stream_t* s) {
    if (get_tag()) {
        get_tag()->represent(s);
    }
    s->printf("%s", asn1_resource::get_instance()->get_type_name(get_type()).c_str());
}

void asn1_object::represent(binary_t* b) {}

void asn1_object::addref() { _ref.addref(); }

void asn1_object::release() { _ref.delref(); }

asn1_namedobject::asn1_namedobject(const std::string& name, asn1_type_t type, asn1_tagged* tag) : asn1_object(name, type, tag) {}

void asn1_namedobject::represent(stream_t* s) {
    s->printf("%s ::= ", get_name().c_str());
    if (get_tag()) {
        get_tag()->represent(s);
    }
    s->printf(" %s ", asn1_resource::get_instance()->get_type_name(get_type()).c_str());
}

void asn1_namedobject::represent(binary_t* b) {}

asn1_type_defined::asn1_type_defined(const std::string& name, asn1_tagged* tag) : asn1_namedobject(name, asn1_type_unknown, tag) {}

void asn1_type_defined::represent(stream_t* s) {
    if (get_tag()) {
        get_tag()->represent(s);
    }
    s->printf("%s", get_name().c_str());
}

void asn1_type_defined::represent(binary_t* b) {}

asn1_type::asn1_type(asn1_type_t type, asn1_tagged* tag) : asn1_object(type, tag) {}

void asn1_type::represent(stream_t* s) {
    if (get_tag()) {
        get_tag()->represent(s);
    }
    s->printf("%s", asn1_resource::get_instance()->get_type_name(get_type()).c_str());
}

void asn1_type::represent(binary_t* b) {}

asn1_namedtype::asn1_namedtype(const std::string& name, asn1_object* object) : asn1_namedobject(name, asn1_type_pair), _object(object) {}

void asn1_namedtype::represent(stream_t* s) {
    s->printf("%s", get_name().c_str());
    s->printf(" ");
    _object->represent(s);
}

void asn1_namedtype::represent(binary_t* b) {}

asn1_container::asn1_container(const std::string& name, asn1_tagged* tag) : asn1_namedobject(name, asn1_type_unknown, tag) {}

asn1_container& asn1_container::operator<<(asn1_namedtype* rhs) {
    if (rhs) {
        _list.push_back(rhs);
    }
    return *this;
}

void asn1_container::represent(stream_t* s) {
    switch (get_type()) {
        case asn1_type_sequence:
        case asn1_type_set:
            s->printf("%s ::= ", get_name().c_str());
            break;
        default:
            break;
    }
    if (get_tag()) {
        get_tag()->represent(s);
    }
    s->printf("%s ", asn1_resource::get_instance()->get_type_name(get_type()).c_str());
    switch (get_type()) {
        case asn1_type_sequence_of:
        case asn1_type_set_of:
            s->printf("%s ", get_name().c_str());
            break;
        default:
            break;
    }
    if (get_componenttype()) {
        s->printf("%s ", asn1_resource::get_instance()->get_componenttype_name(get_componenttype()).c_str());
    }
    switch (get_componenttype()) {
        case asn1_optional:
            break;
        default:
            s->printf("{");
            for (auto iter = _list.begin(); iter != _list.end(); iter++) {
                if (_list.begin() != iter) {
                    s->printf(", ");
                }
                (*iter)->represent(s);
            }
            s->printf("}");
            break;
    }
}

void asn1_container::represent(binary_t* b) {}

}  // namespace io
}  // namespace hotplace
