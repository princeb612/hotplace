/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_publisher.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/basic/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_enum.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_namednumberlist.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_referenced_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_sequence.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tagged_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_unknown_container.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/builtin/asn1_bitstring.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/builtin/asn1_integer.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_builder.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_publisher.hpp>
#include <hotplace/sdk/io/parser/parse_tree.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>

namespace hotplace {
namespace io {

asn1_publisher::asn1_publisher() {}

asn1_publisher::~asn1_publisher() {}

// PoC
// fast throw
return_t asn1_publisher::build(const parse_tree* pt, asn1_object** object) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pt || nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        *object = nullptr;

        prepare();

        asn1_publisher_context context;

        auto lambda = [&](parser_action_t action, parse_treenode* node) -> return_t {
            return_t test = errorcode_t::success;
            if (parser_action_t::shift == action) {
                asn1_semantic_node asn;
                asn.symbol = node->symbol;
                asn.value = node->value;
                context.push(std::move(asn));
            } else if (parser_action_t::reduce == action) {
                auto iter = _handler_map.find(node->symbol);
                if (_handler_map.end() != iter) {
                    test = iter->second(node, context);
                } else {
                    auto size = node->sizeof_rhs();
                    if (context.size() < size)
                        test = errorcode_t::invalid_context;
                    else
                        test = default_handler(node, context);
                }
            }
            return test;
        };
        parse_tree_visitor visitor(lambda);
        ret = pt->accept(&visitor);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (1 != context.size()) {
            ret = errorcode_t::internal_error;  // not implemented
            __leave2;
        }

        auto top = context.pop();
        *object = top.object;
        top.release();  // *object own top.object
    }
    __finally2 {}
    return ret;
}

// PoC
// fast throw
void asn1_publisher::prepare() {
    // default_handler
    //   DefinedType
    //   TypeBase
    //   TypeSpec

    auto resource = asn1_resource::get_instance();

    add_handler("Assignment", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        // production("Assignment", {"DefinedType", "::=", "TypeSpec"})
        // production("Assignment", {"DefinedType", "::=", "TypeSpec", "Constraint"})

        auto size = node->sizeof_rhs();  // 3 or 4
        std::vector<asn1_semantic_node> rhs(size);
        for (size_t i = 0; i < size; ++i) {
            rhs[size - 1 - i] = context.pop();
        }

        auto& rhs_typespec = rhs[2];
        auto& rhs_deftype = rhs[0];

        asn1_semantic_node asn;
        asn.symbol = node->symbol;
        asn.object = asn1_referenced_type::define(rhs_deftype.value, rhs_typespec.object);

        rhs_typespec.release();  // asn own rhs_typespec.object

        context.push(std::move(asn));

        return errorcode_t::success;
    });
    add_handler("SimpleType", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        auto size = node->sizeof_rhs();  // 1, 4
        std::vector<asn1_semantic_node> rhs(size);
        for (size_t i = 0; i < size; ++i) {
            rhs[size - 1 - i] = context.pop();
        }

        auto& rhs_simpletype = rhs[0];
        auto entity = resource->get_entity(rhs_simpletype.symbol);  // BOOLEAN, ..., ANY

        auto obj = asn1_builder::build(entity);
        if (4 == size) {
            // production("SimpleType", {"INTEGER", "{", "EnumList", "}"})
            // production("SimpleType", {"BIT STRING", "{", "EnumList", "}"})
            auto& rhs_enumlist = rhs[2];
            auto container = static_cast<asn1_namednumberlist*>(rhs_enumlist.object);
            if ("INTEGER" == rhs_simpletype.symbol) ((asn1_integer*)obj)->add(*container);
            if ("BIT STRING" == rhs_simpletype.symbol) ((asn1_bitstring*)obj)->add(*container);
        }

        asn1_semantic_node asn(std::move(rhs_simpletype));
        asn.object = obj;
        asn.symbol = node->symbol;

        context.push(std::move(asn));

        return errorcode_t::success;
    });
    add_handler("EnumType", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        auto size = node->sizeof_rhs();
        std::vector<asn1_semantic_node> rhs(size);
        for (size_t i = 0; i < size; ++i) {
            rhs[size - 1 - i] = context.pop();
        }

        auto& rhs_simpletype = rhs[0];
        auto& rhs_enumlist = rhs[2];

        // auto entity = resource->get_entity(rhs_simpletype.symbol);  // ENUMBERATED
        auto container = static_cast<asn1_namednumberlist*>(rhs_enumlist.object);

        auto obj = new asn1_enum;
        obj->add(*container);

        asn1_semantic_node asn(std::move(rhs_simpletype));
        asn.object = obj;
        asn.symbol = node->symbol;

        context.push(std::move(asn));

        return errorcode_t::success;
    });
    add_handler("TagPrefix", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        // production("TagPrefix", {"[", "TagClass", symnum, "]"})
        // production("TagPrefix", {"[", symnum, "]"})

        auto size = node->sizeof_rhs();  // 3 or 4

        context.pop();                            // ]
        auto tagnum = context.pop();              // number
        asn1_semantic_node tagclass;              // CONTEXT
        if (4 == size) tagclass = context.pop();  // UNIVERSAL, APPLICATION, PRIVATE
        context.pop();                            // [

        asn1_semantic_node asn;
        asn.symbol = node->symbol;
        asn.object = asn1_builder::buildtag(tagclass.value, atoi(tagnum.value.c_str()));

        context.push(std::move(asn));

        return errorcode_t::success;
    });
    add_handler("TaggedType", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        // production("TaggedType", {"TagPrefix", "TagSpec", "TypeSpec"})
        // production("TaggedType", {"TagPrefix", "TypeSpec"})

        auto size = node->sizeof_rhs();

        auto rhs_typespec = context.pop();           // asn1_object*
        asn1_semantic_node rhs_tagspec;              // "" AUTOMATIC
        if (3 == size) rhs_tagspec = context.pop();  // EXPLICIT, IMPLICIT
        auto rhs_tagprefix = context.pop();          // asn1_tag

        auto tagobj = static_cast<asn1_tag*>(rhs_tagprefix.object);
        if (nullptr == tagobj) return errorcode_t::bad_data;

        if (3 == size) {
            if ("IMPLICIT" == rhs_tagspec.value)
                tagobj->as_implicit();
            else if ("EXPLICIT" == rhs_tagspec.value)
                tagobj->as_explicit();
        }

        asn1_semantic_node asn;
        asn.symbol = node->symbol;
        asn.object = new asn1_tagged_type(tagobj, rhs_typespec.object);

        // asn own rhs_tagprefix.object and rhs_typespec.object
        rhs_tagprefix.release();
        rhs_typespec.release();

        context.push(std::move(asn));

        return errorcode_t::success;
    });
    add_handler("ReferencedType", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        return_t ret = errorcode_t::success;
        __try2 {
            // pop and push, simply modify
            auto& top = context.top();
            top.symbol = node->symbol;
            top.object = asn1_referenced_type::refer(top.value);
        }
        __finally2 {}
        return ret;
    });
    add_handler("Field", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        // production("Field", {symid, "TypeSpec"})
        // production("Field", {symid, "TypeSpec", "Constraint"})
        // production("Field", {symid, "TypeSpec", "FieldOpt"})
        // production("Field", {symid, "TypeSpec", "Constraint", "FieldOpt"})

        auto size = node->sizeof_rhs();
        std::vector<asn1_semantic_node> rhs(size);
        for (size_t i = 0; i < size; ++i) {
            rhs[size - 1 - i] = context.pop();
        }

        auto& rhs_typespec = rhs[1];  // TypeSpec
        auto& rhs_symid = rhs[0];     // symid or symuser

        if (rhs_typespec.object) rhs_typespec.object->set_name(rhs_symid.value);

        asn1_semantic_node asn;
        asn.symbol = node->symbol;
        asn.object = rhs_typespec.object;

        rhs_typespec.release();  // asn own rhs_typespec.object

        context.push(std::move(asn));

        return errorcode_t::success;
    });
    add_handler("FieldList", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        // production("FieldList", {"FieldList", ",", "Field"})
        // production("FieldList", {"Field"})

        auto size = node->sizeof_rhs();

        auto rhs_field = context.pop();
        if (1 == size) {
            auto container = new asn1_unknown_container;
            *container << rhs_field.object;

            rhs_field.release();  // container own object

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            asn.object = container;

            context.push(std::move(asn));
        } else if (3 == size) {
            context.pop();  // ","
            auto rhs_fieldlist = context.pop();

            auto container = static_cast<asn1_unknown_container*>(rhs_fieldlist.object);
            *container << rhs_field.object;

            rhs_field.release();  // container own object

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            asn.object = container;

            rhs_fieldlist.release();  // asn own container

            context.push(std::move(asn));
        }

        return errorcode_t::success;
    });
    add_handler("StatementSequence", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        // production("StatementSequence", {"SEQUENCE", "Constraint", "{", "FieldList", "}"})
        // production("StatementSequence", {"SEQUENCE", "{", "FieldList", "}"})
        // production("StatementSequence", {"SEQUENCE", "Constraint", "{", "}"})
        // production("StatementSequence", {"SEQUENCE", "{", "}"})

        auto size = node->sizeof_rhs();
        std::vector<asn1_semantic_node> rhs(size);
        std::unordered_map<std::string, size_t> index;
        for (size_t i = 0; i < size; ++i) {
            size_t idx = size - 1 - i;
            rhs[idx] = context.pop();
            auto& it = rhs[idx];
            index.emplace(it.symbol, idx);
        }

        auto sequence = new asn1_sequence;

        asn1_unknown_container* container = nullptr;
        auto iter = index.find("FieldList");
        if (index.end() != iter) {
            auto& rhs_fieldlist = rhs[iter->second];
            container = static_cast<asn1_unknown_container*>(rhs_fieldlist.object);
            sequence->set(std::move(*container));
            rhs_fieldlist.release();
        }

        asn1_semantic_node asn;
        asn.symbol = node->symbol;
        asn.object = sequence;
        context.push(std::move(asn));

        return errorcode_t::success;
    });
    add_handler("EnumItem", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        // production("EnumItem", {symid, "(", symnum, ")"})

        auto size = node->sizeof_rhs();
        std::vector<asn1_semantic_node> rhs(size);
        for (size_t i = 0; i < size; ++i) {
            rhs[size - 1 - i] = context.pop();
        }

        auto& rhs_symid = rhs[0];
        auto& rhs_symnum = rhs[2];

        auto container = new asn1_namednumberlist;
        container->add(rhs_symid.value, atoi(rhs_symnum.value.c_str()));

        asn1_semantic_node asn;
        asn.symbol = node->symbol;
        asn.object = container;
        context.push(std::move(asn));

        return errorcode_t::success;
    });
    add_handler("EnumList", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        // production("EnumList", {"EnumList", ",", "EnumItem"})
        // production("EnumList", {"EnumItem"})

        auto size = node->sizeof_rhs();

        auto rhs_enumitem = context.pop();
        if (1 == size) {
            asn1_semantic_node asn(std::move(rhs_enumitem));
            asn.symbol = node->symbol;
            context.push(std::move(asn));
        } else if (3 == size) {
            context.pop();  // ","
            auto rhs_enumlist = context.pop();

            auto item_container = static_cast<asn1_namednumberlist*>(rhs_enumitem.object);
            auto container = static_cast<asn1_namednumberlist*>(rhs_enumlist.object);
            container->add(*item_container);

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            asn.object = container;

            rhs_enumlist.release();  // asn own container

            context.push(std::move(asn));
        }

        return errorcode_t::success;
    });
}

return_t asn1_publisher::default_handler(parse_treenode* node, asn1_publisher_context& context) {
    return_t ret = errorcode_t::success;

    // pop and push
    // simply modify top

    auto& top = context.top();
    top.symbol = node->symbol;

    return ret;
}

}  // namespace io
}  // namespace hotplace
