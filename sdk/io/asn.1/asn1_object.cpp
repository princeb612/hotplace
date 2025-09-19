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

#include <hotplace/sdk/io/asn.1/asn1_container.hpp>
#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/asn1_visitor.hpp>
#include <hotplace/sdk/io/asn.1/template.hpp>

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
                case asn1_type_generalizedtime:
                    enc.encode(*b, get_type(), _var);
                    break;
                case asn1_type_bitstring:
                    enc.bitstring(*b, _var.to_str());
                    break;
                case asn1_type_octstring:
                    enc.octstring(*b, _var.to_str());
                    break;
                case asn1_type_cstring:
                case asn1_type_generalstring:
                case asn1_type_ia5string:
                case asn1_type_printstring:
                case asn1_type_t61string:
                case asn1_type_universalstring:
                case asn1_type_visiblestring:
                    enc.primitive(*b, get_type(), _var.to_str());
                    break;
                case asn1_type_objid:
                    enc.oid(*b, _var.to_str());
                    break;
                case asn1_type_reloid:
                    enc.reloid(*b, _var.to_str());
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

}  // namespace io
}  // namespace hotplace
