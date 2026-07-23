/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/encoding/base128.hpp>
#include <hotplace/sdk/base/encoding/base16.hpp>
#include <hotplace/sdk/base/nostd/atoi.hpp>
#include <hotplace/sdk/base/system/ieee754.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_any.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_builtin_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_container.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_der_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_notation_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_tagged_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_weak_typed.hpp>
#include <hotplace/sdk/io/asn.1/basic/builtin/asn1_bitstring.hpp>
#include <hotplace/sdk/io/asn.1/basic/builtin/asn1_integer.hpp>
#include <hotplace/sdk/io/basic/oid.hpp>

namespace hotplace {
namespace io {

asn1::asn1() {
    _shared.make_share(this);
    // get_parser().get_config().set("handle_quot_as_unquoted", 1);
    // get_parser().add_token("::=", token_assign).add_token("--", token_comments);
}

asn1::asn1(const asn1& other) : asn1() {
    for (auto item : other._types) {
        add(item->clone());
    }
}

asn1::~asn1() { clear(); }

asn1& asn1::operator=(const asn1& other) {
    for (auto item : other._types) {
        add(item->clone());
    }
    return *this;
}

asn1* asn1::clone() { return new asn1(*this); }

asn1_object* asn1::make_builtin_type(asn1_entity_t entity, std::function<void(asn1_object*)> f) {
    asn1_object* object = nullptr;
    switch (entity) {
        case asn1_entity_integer:
            object = new asn1_integer;
            break;
        case asn1_entity_bitstring:
            object = new asn1_bitstring;
            break;
        case asn1_entity_boolean:
        case asn1_entity_octstring:
        case asn1_entity_null:
        case asn1_entity_oid:
        case asn1_entity_objdesc:
        case asn1_entity_extern:
        case asn1_entity_real:
        case asn1_entity_enum:
        case asn1_entity_embedpdv:
        case asn1_entity_utf8string:
        case asn1_entity_reloid:
        case asn1_entity_sequence:
        case asn1_entity_set:
        case asn1_entity_numstring:
        case asn1_entity_printstring:
        case asn1_entity_teletexstring:
        // case asn1_entity_t61string:
        case asn1_entity_videotexstring:
        case asn1_entity_ia5string:
        case asn1_entity_utctime:
        case asn1_entity_generalizedtime:
        case asn1_entity_graphicstring:
        case asn1_entity_visiblestring:
        // case asn1_entity_iso646string:
        case asn1_entity_generalstring:
        case asn1_entity_universalstring:
        case asn1_entity_cstring:
        case asn1_entity_bmpstring:
        case asn1_entity_date:
        case asn1_entity_timeofday:
        case asn1_entity_datetime:
        case asn1_entity_duration:
            object = new asn1_builtin_type(entity);
            break;
        default:
            break;
    }
    if (object && f) {
        f(object);
    }
    return object;
}

asn1& asn1::add(asn1_object* item) {
    if (item) {
        _types.push_back(item);
        const std::string& name = item->get_name();
        if (false == name.empty()) {
            _dictionary.emplace(name, item);
        }
    }
    return *this;
}

asn1& asn1::add(asn1_object* item, std::function<void(asn1_object*)> f) {
    if (item && f) {
        f(item);
        add(item);
    }
    return *this;
}

asn1& asn1::operator<<(asn1_object* item) { return add(item); }

return_t asn1::read(const byte_t* stream, size_t size, size_t& pos) {
    asn1_weak_typed awt;
    auto test = awt.read(stream, size, pos);
    if (errorcode_t::success != test) return test;

    // build asn1_object
    // auto value = object->instantiate();
    // ret = asn1_encode::read(stream, size, pos, entity, len, value);

    using asn1_tlv_t = asn1_weak_typed::asn1_tlv_t;
    // using TLV_tree = t_tree<asn1_tlv_t>;
    using TLV_node = t_treenode<asn1_tlv_t>;

    auto lambda = [&](TLV_node* node) -> void {
        if (node->is_leaf()) {
            const auto& leaf_tlv = node->get();
            asn1_object* obj = nullptr;

            if (asn1_class_universal == (leaf_tlv.ident & asn1_class_mask)) {
                obj = new asn1_builtin_type((asn1_entity_t)leaf_tlv.tag);
            } else {
                obj = new asn1_tagged_type(leaf_tlv.ident & asn1_class_mask, leaf_tlv.tag, leaf_tlv.mode, new asn1_any);
            }
            if (leaf_tlv.ident & asn1_tag_constructed) {
                obj->as_constructed();
            }

            auto temp = node->parent();
            while (awt._tree.root() != temp) {
                const auto& tlv = temp->get();
                obj = new asn1_tagged_type(tlv.ident & asn1_class_mask, tlv.tag, tlv.mode, obj);
                if (tlv.ident & asn1_tag_constructed) {
                    obj->as_constructed();
                }
                temp = temp->parent();
            }

            asn1_object* type = obj;
            asn1_value* value = obj->instantiate();

            if (asn1_class_universal == (leaf_tlv.ident & asn1_class_mask)) {
                auto pos = leaf_tlv.pos;
                asn1_encode::read(stream, size, pos, (asn1_entity_t)leaf_tlv.tag, leaf_tlv.len, value);
            } else {
                variant vt(stream + leaf_tlv.pos, leaf_tlv.len);
                value->set(std::move(vt));
            }

            _types.push_back(type);
            _values.push_back(value);
        }
    };
    t_tree_visitor<asn1_tlv_t> visitor(lambda);
    visitor.visit(&awt._tree);

    return errorcode_t::success;
}

void asn1::for_each(std::function<void(asn1_object*)> f) const {
    for (const auto& item : _types) {
        f(item);
    }
}

void asn1::for_each(std::function<void(asn1_value*)> f) const {
    for (const auto& item : _values) {
        f(item);
    }
}

void asn1::notation(stream_t* s) {
    asn1_notation_visitor notation(s);
    auto nl = _types.size() > 1;
    for (auto item : _types) {
        item->accept(&notation);
        if (nl) s->printf("\n");
    }
}

void asn1::publish(stream_t* s) {
    auto nl = _types.size() > 1;
    for (auto item : _values) {
        asn1_notation_visitor notation(s, item);
        item->get_schema()->accept(&notation);
        if (nl) s->printf("\n");
    }
}

void asn1::publish(binary_t* b) {
    for (auto item : _values) {
        asn1_der_visitor encoder(b, item);
        item->get_schema()->accept(&encoder);
    }
}

void asn1::clear() {
    for (auto item : _types) item->release();
    for (auto item : _values) item->release();
    _types.clear();
    _values.clear();
}

void asn1::addref() { _shared.addref(); }

void asn1::release() { _shared.delref(); }

// parser& asn1::get_parser() { return _parser; }
//
// const parser::context& asn1::get_rule_context() const { return _rule; }

}  // namespace io
}  // namespace hotplace
