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

#include <hotplace/sdk/io/asn.1/asn1_composite.hpp>
#include <hotplace/sdk/io/asn.1/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/asn1_visitor.hpp>
#include <hotplace/sdk/io/asn.1/template.hpp>

namespace hotplace {
namespace io {

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

asn1_composite::~asn1_composite() {
    if (_object) {
        _object->release();
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

}  // namespace io
}  // namespace hotplace
