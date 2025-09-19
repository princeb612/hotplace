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

#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/asn1_visitor.hpp>
#include <hotplace/sdk/io/asn.1/template.hpp>

namespace hotplace {
namespace io {

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

}  // namespace io
}  // namespace hotplace
