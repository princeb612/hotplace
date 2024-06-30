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
#include <sdk/io/asn.1/asn1_visitor.hpp>
#include <sdk/io/asn.1/template.hpp>

namespace hotplace {
namespace io {

asn1_object::asn1_object(asn1_type_t type, asn1_tag* tag) : _type(type), _tag(tag), _component_type(0), _parent(nullptr), _object(nullptr) {
    _ref.make_share(this);
}

asn1_object::asn1_object(const std::string& name, asn1_type_t type, asn1_tag* tag)
    : _name(name), _type(type), _tag(tag), _component_type(0), _parent(nullptr), _object(nullptr) {
    _ref.make_share(this);
}

asn1_object::asn1_object(const std::string& name, asn1_object* object, asn1_tag* tag)
    : _name(name), _type(asn1_type_named), _tag(tag), _component_type(0), _parent(nullptr), _object(object) {
    _ref.make_share(this);
}

asn1_object::asn1_object(const asn1_object& rhs)
    : _name(rhs._name), _type(rhs._type), _tag(nullptr), _component_type(rhs._component_type), _parent(nullptr), _object(nullptr) {
    _ref.make_share(this);
    if (rhs._tag) {
        _tag = (asn1_tag*)rhs._tag->clone();
    }
    if (rhs._object) {
        _object = rhs._object->clone();
    }
}

asn1_object::~asn1_object() { clear(); }

asn1_object* asn1_object::clone() { return new asn1_object(*this); }

asn1_object& asn1_object::set_parent(asn1_object* parent) {
    _parent = parent;
    return *this;
}

asn1_object* asn1_object::get_parent() const { return _parent; }

const std::string& asn1_object::get_name() const { return _name; }

asn1_object& asn1_object::set_type(asn1_type_t type) {
    _type = type;
    return *this;
}

asn1_type_t asn1_object::get_type() const { return _type; }

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

variant& asn1_object::get_data() { return _var; }

const variant& asn1_object::get_data() const { return _var; }

void asn1_object::accept(asn1_visitor* v) { v->visit(this); }

void asn1_object::represent(stream_t* s) {
    if (s) {
        switch (get_type()) {
            case asn1_type_named:
                s->printf("%s ", get_name().c_str());
                if (_object) {
                    _object->represent(s);
                }
                break;
            case asn1_type_referenced:
                if (get_tag()) {
                    get_tag()->represent(s);
                }
                s->printf("%s", get_name().c_str());
                break;
            default:
                if (false == get_name().empty()) {
                    s->printf("%s ", get_name().c_str());
                    if (nullptr == get_parent()) {
                        s->printf("::= ");
                    }
                }
                if (get_tag()) {
                    get_tag()->represent(s);
                }
                s->printf("%s", asn1_resource::get_instance()->get_type_name(get_type()).c_str());
                break;
        }
    }
}

void asn1_object::represent(binary_t* b) {
    if (b) {
        asn1_type_t type = get_type();

        // Type1 ::= VisibleString
        //      1A 05 4A 6F 6E 65 73
        //      -- VisibleString
        // Type2 ::= [Application 3] implicit Type1
        //      43 05 4A 6F 6E 65 73
        //      -- asn1_class_application | 3
        // Type3 ::= [2] Type2
        //      A2 07 43 05 4A 6F 6E 65 73
        //      -- asn1_class_context | asn1_tag_constructed | 2
        // Type4 ::= [Application 7] implicit Type3
        //      67 07 43 05 4A 6F 6E 65 73
        //      -- asn1_class_application | asn1_tag_constructed | 7
        // Type5 ::= [2] implicit Type2
        //      82 05 4A 6F 6E 65 73
        //      -- asn1_class_context | 2

        if (get_tag()) {
            get_tag()->represent(b);
            if (get_tag()->is_implicit()) {
                type = asn1_type_tagged;
            } else {
                //
            }
        }

        if (type == asn1_type_named) {
            if (_object) {
                _object->represent(b);
            }
        } else {
            asn1_encode enc;
            switch (type) {
                case asn1_type_tagged:
                    enc.encode(*b, get_type(), _var.to_bin());
                    break;
                case asn1_type_boolean:
                case asn1_type_integer:
                case asn1_type_null:
                case asn1_type_real:
                    enc.encode(*b, get_type(), _var);
                    break;
                case asn1_type_bitstring:
                    enc.bitstring(*b, _var.to_str());
                    break;
                case asn1_type_ia5string:
                case asn1_type_visiblestring:
                case asn1_type_generalstring:
                case asn1_type_universalstring:
                case asn1_type_cstring:
                    enc.primitive(*b, get_type(), _var.to_str());
                    break;
            }
        }
    }
}

void asn1_object::clear() {
    if (_tag) {
        _tag->release();
        _tag = nullptr;
    }
    if (_object) {
        _object->release();
        _object = nullptr;
    }
}

void asn1_object::addref() { _ref.addref(); }

void asn1_object::release() { _ref.delref(); }

asn1_tag::asn1_tag(int cnumber, asn1_tag* tag)
    : asn1_object(asn1_type_tagged, tag), _class_type(asn1_class_empty), _class_number(cnumber), _tag_mode(0), _suppress(false) {}

asn1_tag::asn1_tag(int cnumber, int tmode, asn1_tag* tag)
    : asn1_object(asn1_type_tagged, tag), _class_type(asn1_class_empty), _class_number(cnumber), _tag_mode(tmode), _suppress(false) {}

asn1_tag::asn1_tag(int ctype, int cnumber, int tmode, asn1_tag* tag)
    : asn1_object(asn1_type_tagged, tag), _class_type(ctype), _class_number(cnumber), _tag_mode(tmode), _suppress(false) {}

asn1_tag::asn1_tag(const asn1_tag& rhs)
    : asn1_object(rhs), _class_type(rhs._class_type), _class_number(rhs._class_number), _tag_mode(rhs._tag_mode), _suppress(rhs._suppress) {}

asn1_object* asn1_tag::clone() { return new asn1_tag(*this); }

int asn1_tag::get_class() const { return _class_type; }

int asn1_tag::get_class_number() const { return _class_number; }

int asn1_tag::get_tag_type() const { return _tag_mode; }

bool asn1_tag::is_implicit() const {
    bool ret = false;
    if (get_tag()) {
        if (asn1_implicit == get_tag()->get_tag_type()) {
            ret = true;
        }
    } else {
        if (asn1_implicit == get_tag_type()) {
            ret = true;
        }
    }
    return ret;
}

void asn1_tag::suppress() { _suppress = true; }

void asn1_tag::unsuppress() { _suppress = false; }

bool asn1_tag::is_suppressed() const { return _suppress; }

void asn1_tag::represent(stream_t* s) {
    if (s) {
        s->printf("[");
        s->printf("%s", asn1_resource::get_instance()->get_class_name(get_class()).c_str());
        if (asn1_class_empty != get_class()) {
            s->printf(" ");
        }
        s->printf("%i", get_class_number());
        s->printf("] ");
        if (get_tag_type()) {
            s->printf("%s ", asn1_resource::get_instance()->get_tagtype_name(get_tag_type()).c_str());
        }
    }
}

void asn1_tag::represent(binary_t* b) {
    if (b && (false == is_suppressed())) {
        bool tagmode_explicit = true;
        if (get_tag()) {
            get_tag()->represent(b);
            if (asn1_implicit == get_tag()->get_tag_type()) {
                tagmode_explicit = false;
            } else {
                //
            }
        }
        if (tagmode_explicit) {
            asn1_encode enc;
            uint8 t = 0;
            if (asn1_type_constructed == get_type()) {
                t = asn1_tag_constructed;
            }
            enc.encode(*b, t | get_class(), get_class_number());
        }
    }
}

asn1_composite::asn1_composite(asn1_type_t type, asn1_object* obj, asn1_tag* tag) : asn1_object(asn1_type_primitive, tag), _object(obj) {
    if (asn1_type_constructed == type) {
        as_constructed();
    } else {
        as_primitive();
    }
}

asn1_composite::asn1_composite(const asn1_composite& rhs) : asn1_object(rhs), _object(nullptr) {
    if (rhs._object) {
        _object = rhs._object->clone();
    }
}

asn1_object* asn1_composite::clone() { return new asn1_composite(*this); }

asn1_composite& asn1_composite::as_primitive() {
    set_type(asn1_type_primitive);
    asn1_tag* temp = get_tag();
    while (temp) {
        temp->set_type(asn1_type_tagged);
        temp = temp->get_tag();
    }
    if (get_object() && get_tag()) {
        if (get_object()->get_tag() && get_tag()->is_implicit()) {
            get_object()->get_tag()->suppress();
        } else {
            get_object()->get_tag()->unsuppress();
        }
    }
    return *this;
}

asn1_composite& asn1_composite::as_constructed() {
    set_type(asn1_type_constructed);
    asn1_tag* temp = get_tag();
    while (temp) {
        temp->set_type(asn1_type_constructed);
        temp = temp->get_tag();
    }
    if (get_object() && get_tag()) {
        if (get_object()->get_tag() && get_tag()->is_implicit()) {
            get_object()->get_tag()->suppress();
        } else {
            get_object()->get_tag()->unsuppress();
        }
    }
    return *this;
}

asn1_object* asn1_composite::get_object() { return _object; }

void asn1_composite::clear() {
    if (_object) {
        _object->release();
        _object = nullptr;
    }
}

void asn1_composite::represent(stream_t* s) {
    if (s) {
        if (get_tag()) {
            get_tag()->represent(s);
        }
        if (get_object()) {
            get_object()->represent(s);
        }
    }
}

void asn1_composite::represent(binary_t* b) {
    if (b) {
        size_t pos = 0;
        if (get_tag()) {
            get_tag()->represent(b);
            if (false == get_tag()->is_implicit()) {
                pos = b->size();
            }
        }
        if (get_object()) {
            get_object()->get_data() = get_data();
            get_object()->represent(b);
        }
        if (get_tag()) {
            if (false == get_tag()->is_implicit()) {
                t_asn1_length_octets<size_t>(*b, b->size() - pos, pos);
            }
        }
    }
}

asn1_container::asn1_container(const std::string& name, asn1_tag* tag) : asn1_object(name, asn1_type_primitive, tag) {}

asn1_container::asn1_container(const asn1_container& rhs) : asn1_object(rhs) {
    for (auto item : rhs._list) {
        *this << item->clone();
    }
}

asn1_object* asn1_container::clone() { return new asn1_container(*this); }

asn1_container& asn1_container::operator<<(asn1_object* rhs) {
    if (rhs) {
        _list.push_back(rhs);
        rhs->set_parent(this);
    }
    return *this;
}

void asn1_container::represent(stream_t* s) {
    if (s) {
        if (false == get_name().empty()) {
            switch (get_type()) {
                case asn1_type_sequence:
                case asn1_type_set:
                    s->printf("%s ::= ", get_name().c_str());
                    break;
                default:
                    break;
            }
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
}

void asn1_container::represent(binary_t* b) {}

void asn1_container::addref() {
    for (auto item : _list) {
        item->addref();
    }
}

void asn1_container::release() {
    for (auto item : _list) {
        item->release();
    }
}

}  // namespace io
}  // namespace hotplace
