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

asn1_tagged::asn1_tagged(asn1_class_t c, int cn, int tt) : asn1_object(asn1_type_tag), _class(c), _class_number(cn), _tag_type(tt) {}

asn1_class_t asn1_tagged::get_class() { return _class; }

int asn1_tagged::get_class_number() { return _class_number; }

int asn1_tagged::get_tag_type() { return _tag_type; }

void asn1_tagged::represent(stream_t* s) {
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

void asn1_tagged::represent(binary_t* b) {
    //
}

}  // namespace io
}  // namespace hotplace
