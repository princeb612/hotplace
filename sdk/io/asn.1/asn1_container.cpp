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

#include <sdk/io/asn.1/asn1_container.hpp>
#include <sdk/io/asn.1/asn1_resource.hpp>
#include <sdk/io/asn.1/asn1_tag.hpp>
#include <sdk/io/asn.1/asn1_visitor.hpp>
#include <sdk/io/asn.1/template.hpp>

namespace hotplace {
namespace io {

asn1_container::asn1_container(asn1_tag* tag) : asn1_object("", asn1_type_primitive, tag) {}

asn1_container::asn1_container(const std::string& name, asn1_tag* tag) : asn1_object(name, asn1_type_primitive, tag) {}

asn1_container::asn1_container(const asn1_container& rhs) : asn1_object(rhs) {
    for (auto item : rhs._list) {
        *this << item->clone();
    }
}

asn1_container::~asn1_container() {
    for (auto item : _list) {
        item->release();
    }
}

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
