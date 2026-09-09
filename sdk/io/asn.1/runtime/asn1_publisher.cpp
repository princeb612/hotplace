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
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_referenced_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tagged_type.hpp>
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

        auto lambda = [&](parser_action_t action, parse_treenode* node) -> void {
            if (parser_action_t::shift == action) {
                asn1_semantic_node asn;
                asn.symbol = node->symbol;
                asn.value = node->value;
                context.push(std::move(asn));
            } else if (parser_action_t::reduce == action) {
                auto iter = _handler_map.find(node->symbol);
                if (_handler_map.end() != iter) {
                    ret = iter->second(node, context);
                } else {
                    ret = default_handler(node, context);
                }
            }
        };
        parse_tree_visitor visitor(lambda);
        pt->accept(&visitor);

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

    register_handler("Assignment", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        return_t ret = errorcode_t::success;
        __try2 {
            // production("Assignment", {"DefinedType", "::=", "TypeSpec"})
            // production("Assignment", {"DefinedType", "::=", "TypeSpec", "Constraint"})

            auto size = node->sizeof_rhs();  // 3 or 4
            if (context.size() < size) {
                ret = errorcode_t::invalid_context;
                __leave2;
            };

            auto rhs = context.pop();
            if (nullptr == rhs.object) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
            auto assign = context.pop();
            // asn1_semantic_node constraints;
            if (size > 3) {
                // TODO
                // constraints = context.pop();

                ret = errorcode_t::not_implemented;
                __leave2;
            }
            auto lhs = context.pop();

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            asn.object = asn1_referenced_type::define(lhs.value, rhs.object);

            rhs.release();  // asn own rhs.object

            context.push(std::move(asn));
        }
        __finally2 {}
        return ret;
    });
    register_handler("SimpleType", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        return_t ret = errorcode_t::success;
        __try2 {
            auto size = node->sizeof_rhs();
            if (1 == size) {
                auto& top = context.top();  // pop and push

                auto entity = resource->get_entity(top.symbol);  // BOOLEAN, ..., ANY
                auto obj = asn1_builder::build(entity);
                if (obj) {
                    top.object = obj;
                    top.symbol = node->symbol;
                } else {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
            } else {
                // production("SimpleType", {"INTEGER", "{", "EnumList", "}"})
                // production("SimpleType", {"BIT STRING", "{", "EnumList", "}"})
                ret = errorcode_t::not_implemented;  // TODO - not yet
                __leave2;
            }
        }
        __finally2 {}
        return ret;
    });
    register_handler("TagPrefix", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        return_t ret = errorcode_t::success;
        __try2 {
            // production("TagPrefix", {"[", "TagClass", symnum, "]"})
            // production("TagPrefix", {"[", symnum, "]"})

            auto size = node->sizeof_rhs();  // 3 or 4
            if (context.size() < size) {
                ret = errorcode_t::invalid_context;
                __leave2;
            };

            context.pop();                            // ]
            auto tagnum = context.pop();              // number
            asn1_semantic_node tagclass;              // CONTEXT
            if (4 == size) tagclass = context.pop();  // UNIVERSAL, APPLICATION, PRIVATE
            context.pop();                            // [

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            asn.object = asn1_builder::buildtag(tagclass.value, atoi(tagnum.value.c_str()));
            context.push(std::move(asn));
        }
        __finally2 {}
        return ret;
    });
    register_handler("TaggedType", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        return_t ret = errorcode_t::success;
        __try2 {
            // production("TagPrefix", {"[", "TagClass", symnum, "]"})
            // production("TagPrefix", {"[", symnum, "]"})

            auto size = node->sizeof_rhs();  // 3 or 4
            if (context.size() < size) {
                ret = errorcode_t::invalid_context;
                __leave2;
            };

            auto typespec = context.pop();  //
            asn1_semantic_node tagspec;     // "" AUTOMATIC
            if (3 == size) tagspec = context.pop();
            auto tagprefix = context.pop();  // asn1_tag

            auto tagobj = static_cast<asn1_tag*>(tagprefix.object);
            if (nullptr == tagobj) {
                ret = errorcode_t::bad_data;
                __leave2;
            }

            if ("IMPLICIT" == tagspec.value)
                tagobj->as_implicit();
            else if ("EXPLICIT" == tagspec.value)
                tagobj->as_explicit();

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            asn.object = new asn1_tagged_type(tagobj, typespec.object);

            // asn own tagprefix.object and typespec.object
            tagprefix.release();
            typespec.release();

            context.push(std::move(asn));
        }
        __finally2 {}
        return ret;
    });
    register_handler("ReferencedType", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
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
    register_handler("Field", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        return_t ret = errorcode_t::success;
        __try2 {
            // production("Field", {symid, "TypeSpec"})
            // production("Field", {symid, "TypeSpec", "Constraint"})
            // production("Field", {symid, "TypeSpec", "FieldOpt"})
            // production("Field", {symid, "TypeSpec", "Constraint", "FieldOpt"})

            auto size = node->sizeof_rhs();
            if (context.size() < size) {
                ret = errorcode_t::invalid_context;
                __leave2;
            };

            if (2 < size) {
                ret = errorcode_t::not_implemented;  // TODO
                __leave2;
            }

            if (3 < size) context.pop();  // TODO
            if (2 < size) context.pop();  // TODO

            asn1_semantic_node ts = context.pop();  // TypeSpec
            asn1_semantic_node id = context.pop();  // symid or symuser

            if (nullptr == ts.object) {
                ret = errorcode_t::internal_error;
                __leave2;
            }

            ts.object->set_name(id.value);

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            asn.object = ts.object;

            ts.release();  // asn own ts.object

            context.push(std::move(asn));
        }
        __finally2 {}
        return ret;
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
