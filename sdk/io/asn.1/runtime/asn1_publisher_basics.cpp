/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_publisher_basics.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *   Considerations for `asn1_runtime_context` in a multi-threaded environment:
 *   - Whenever possible, use `add` and `get` operations that do not modify the current pointer.
 */

#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_choice.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_enum.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_namedlist.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_referenced_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_sequence.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_sequence_of.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_set.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_set_of.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tagged_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_unknown_container.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/builtin/asn1_bitstring.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/builtin/asn1_integer.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_builder.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_publisher.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime_context.hpp>
#include <hotplace/sdk/io/parser/parse_tree.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>

namespace hotplace {
namespace io {

void asn1_publisher::prepare_basics() {
    // Start
    add_handler(
        "ModuleStatementList", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("ModuleStatementList", {"ModuleStatementList", "ModuleStatement"})
            // production("ModuleStatementList", {"ModuleStatement"})

            return errorcode_t::success;
        });
    add_handler(
        "ModuleStatementList", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("ModuleStatementList", {"ModuleStatementList", "ModuleStatement"})
            // production("ModuleStatementList", {"ModuleStatement"})

            auto size = node->sizeof_rhs();
            if (1 == size) {
                auto& top = context.top();
                top.symbol = node->symbol;
            } else {
                auto statement = context.pop();
                context.pop();

                context.push(std::move(statement));
            }

            return errorcode_t::success;
        });
    add_handler(
        "ModuleStatement", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("ModuleStatement", {"ModuleDefinition"})
            // production("ModuleStatement", {"Statement"})

            return errorcode_t::success;
        });
    add_handler(
        "ModuleDefinition", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("ModuleDefinition", {"ModuleIdentifier", "DEFINITIONS", "TagDefault", "ExtensionDefault", symassign, "BEGIN", "ModuleBody", "END"})
            // production("ModuleDefinition", {"ModuleIdentifier", "DEFINITIONS", "TagDefault", symassign, "BEGIN", "ModuleBody", "END"})
            // production("ModuleDefinition", {"ModuleIdentifier", "DEFINITIONS", symassign, "BEGIN", "ModuleBody", "END"})

            auto rtcontext = asn1_runtime_context::get_instance();

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            auto& rhs_id = rhs[0];

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            auto module_id = rhs_id.value;
            auto runtime = rtcontext->add(module_id);

            result.type = asn1_build_t::module_definition;
            result.module_names.push_back(module_id);

            context.get_runtime().as_module();  // as module

            auto rtmodule = rtcontext->add(module_id);
            *rtmodule = std::move(context.get_runtime());

            auto iter = index.find("TagDefault");
            if (index.end() != iter) {
                auto& rhs_tagdefault = rhs[iter->second];
                asn.module.tagdefault = rhs_tagdefault.module.tagdefault;
                runtime->set_tagdefault(asn.module.tagdefault);
            } else {
                runtime->set_tagdefault(asn1_tagdefault);  // MyModule DEFINITIONS ::= BEGIN ...
            }
            iter = index.find("ExtensionDefault");
            if (index.end() != iter) {
                auto& rhs_ext = rhs[iter->second];
                asn.module.extensibility = rhs_ext.module.extensibility;
                runtime->set_extensibility(uint8(asn.module.extensibility));
            }

            context.push(std::move(asn));

            return errorcode_t::success;
        });
    // ModuleIdentifier
    // DefinitiveOidComponentList
    // DefinitiveObjIdComponent
    add_handler(
        "TagDefault", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("TagDefault", {"EXPLICIT", "TAGS"})
            // production("TagDefault", {"IMPLICIT", "TAGS"})
            // production("TagDefault", {"AUTOMATIC", "TAGS"})

            auto rhs_tags = context.pop();
            auto rhs_taggingmode = context.pop();

            asn1_semantic_node asn;
            asn.symbol = node->symbol;

            if ("AUTOMATIC" == rhs_taggingmode.symbol) {
                asn.module.tagdefault = asn1_automatic;
            } else if ("EXPLICIT" == rhs_taggingmode.symbol) {
                // MyModule DEFINITIONS EXPLICIT TAGS ::= BEGIN ...
                asn.module.tagdefault = asn1_explicit;
            } else {
                // MyModule DEFINITIONS IMPLICIT TAGS ::= BEGIN ...
                // MyModule DEFINITIONS AUTOMATIC TAGS ::= BEGIN ...
                asn.module.tagdefault = asn1_implicit;
            }

            context.push(std::move(asn));

            return errorcode_t::success;
        });
    add_handler(
        "ExtensionDefault", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            auto size = node->sizeof_rhs();
            for (size_t i = 0; i < size; ++size) context.pop();

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            asn.module.extensibility = asn1_extensibility_t::extension_implied;

            context.push(std::move(asn));
            return errorcode_t::success;
        });
    add_handler(
        "ModuleBody", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("ModuleBody", {"Exports", "Imports", "AssignmentList"})
            // production("ModuleBody", {"Exports", "AssignmentList"})
            // production("ModuleBody", {"Imports", "AssignmentList"})
            // production("ModuleBody", {"AssignmentList"})
            // production("ModuleBody", {})

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            context.push(std::move(asn));

            return errorcode_t::success;
        });
    add_handler(
        "Exports", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("Exports", {"EXPORTS", "SymbolList", ";"})
            // production("Exports", {"EXPORTS", "ALL", ";"})

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            asn1_exports exports;
            auto iter = index.find("ALL");
            if (index.end() != iter) {
                exports.type = asn1_exports_t::all;
            } else {
                exports.type = asn1_exports_t::list;
                exports.symbols = std::move(context.get_symbols());
            }
            context.get_runtime().export_symbol(std::move(exports));

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            context.push(std::move(asn));

            return errorcode_t::success;
        });
    add_handler(
        "Imports", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("Imports", {"IMPORTS", "SymbolsFromModuleList", ";"})

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            context.push(std::move(asn));

            return errorcode_t::success;
        });
    // SymbolsFromModuleList
    add_handler(
        "SymbolsFromModule", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("SymbolsFromModule", {"SymbolList", "FROM", "ModuleIdentifier"})

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            asn1_symbol_module symbol_module;
            auto iter = index.find("ModuleIdentifier");
            if (index.end() != iter) {
                auto& rhs_moduleid = rhs[iter->second];
                symbol_module.outer_module = rhs_moduleid.value;
            }
            symbol_module.symbols = std::move(context.get_symbols());
            context.get_runtime().import_symbol(std::move(symbol_module));

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            context.push(std::move(asn));

            return errorcode_t::success;
        });
    add_handler(
        "SymbolList", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("SymbolList", {"SymbolList", ",", "Symbol"})
            // production("SymbolList", {"Symbol"})

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            auto iter = index.find("Symbol");
            if (index.end() != iter) {
                auto& rhs_symbol = rhs[iter->second];
                context.get_symbols().push_back(rhs_symbol.value);
            }

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            context.push(std::move(asn));

            return errorcode_t::success;
        });
    // Symbol
    add_handler(
        "StatementList", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("StatementList", {"StatementList", "Statement"})
            // production("StatementList", {"Statement"})

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            asn1_semantic_node asn;
            asn.symbol = node->symbol;

            auto iter = index.find("Statement");
            if (index.end() != iter) {
                auto& rhs_statement = rhs[iter->second];
                asn.object = rhs_statement.object;
                rhs_statement.release();  // asn own object
            }

            context.push(std::move(asn));

            return errorcode_t::success;
        });
    // Statement
    add_handler(
        "AssignmentList", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("AssignmentList", {"AssignmentList", "Assignment"})
            // production("AssignmentList", {"Assignment"})

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            asn1_semantic_node asn;
            asn.symbol = node->symbol;

            auto iter = index.find("Assignment");
            if (index.end() != iter) {
                auto& rhs_assignment = rhs[iter->second];
                asn.object = rhs_assignment.object;
                rhs_assignment.release();  // asn own object
            }

            context.push(std::move(asn));

            return errorcode_t::success;
        });
    // Assignment
    add_handler(
        "TypeAssignment", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("TypeAssignment", {"DefinedType", symassign, "Type"})
            // production("TypeAssignment", {"DefinedType", symassign, "Type", "Constraint"})
            // production("TypeAssignment", {symuserparamtype, "{", "ParameterList", "}", symassign, "Type"})
            // production("TypeAssignment", {symuserparamtype, "{", "ParameterList", "}", symassign, "Type", "Constraint"})

            // auto rtcontext = asn1_runtime_context::get_instance();

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            asn1_semantic_node asn;
            asn.symbol = node->symbol;

            auto iter = index.find("DefinedType");
            if (index.end() != iter) {
                auto& rhs_deftype = rhs[iter->second];

                auto& rhs_typespec = rhs[2];  // "Type"

                asn.object = asn1_referenced_type::define(rhs_deftype.value, rhs_typespec.object);

                iter = index.find("Constraint");
                if (index.end() != iter) {
                    auto& rhs_cons = rhs[iter->second];
                    auto cons = rhs_cons.cons.u;
                    rhs_typespec.object->get_constraints().add(cons);
                    if (asn1_entity_constraint_container != cons->get_entity()) rhs_cons.release();
                }

                {
                    result.type = asn1_build_t::assignments;
                    context.get_runtime().add(asn.object);
                    asn.object->addref();
                }

                rhs_typespec.release();  // asn own rhs_typespec.object
            }
            // TODO parameterized

            context.push(std::move(asn));
            return errorcode_t::success;
        });
    // ValueAssignment
    // ValueElementList
    // DefinedType
    // ParameterList
    // Parameter
    // Type
    // TypeIdentifier
    add_handler(
        "ReferencedTypeSpec", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("ReferencedTypeSpec", {"TypeIdentifier"})

            // pop and push, simply modify
            auto& top = context.top();
            top.symbol = node->symbol;
            top.object = asn1_referenced_type::refer(top.value);

            return errorcode_t::success;
        });
    add_handler(
        "NamedType", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("NamedType", {symid, "Type"})
            auto rhs_typespec = context.pop();  // Type
            auto rhs_symid = context.pop();     // symid or symuser

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            asn.object = rhs_typespec.object;

            rhs_typespec.release();  // asn own rhs_typespec.object

            if (asn.object) {
                asn.object->set_name(rhs_symid.value);
            }

            context.push(std::move(asn));

            return errorcode_t::success;
        });
    add_handler(
        "ComponentType", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("ComponentType", {"NamedType"})
            // production("ComponentType", {"NamedType", "Constraint"})
            // production("ComponentType", {"NamedType", "OptionalitySpec"})
            // production("ComponentType", {"NamedType", "Constraint", "OptionalitySpec"})

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            auto& rhs_namedtype = rhs[0];

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            asn.object = rhs_namedtype.object;

            rhs_namedtype.release();  // asn own rhs_namedtype.object

            if (asn.object) {
                auto iter = index.find("OptionalitySpec");
                if (index.end() != iter) {
                    auto& rhs_fieldopt = rhs[iter->second];

                    /**
                     * To ensure compliance with the ASN.1 standard grammar and prevent Shift/Reduce conflicts in the LALR(1) parser, the grammar was kept clean by
                     * restricting the `DEFAULT` syntax to the `ComponentType` production level. Instead, leveraging the AST structure where `TaggedTypeSpec` acts as a
                     * decorator, the issue was resolved by clearly separating responsibilities so that the `Publisher` layer propagates (unwraps) the `DEFAULT` option to
                     * the actual object contained within the `TaggedTypeSpec`.
                     */
                    if (asn1_entity_tagged_type == asn.object->get_entity()) {
                        auto tagobj = dynamic_cast<asn1_tagged_type*>(asn.object);
                        if (tagobj) {
                            auto child = tagobj->get_object();
                            if (child) {
                                child->set_option(rhs_fieldopt.option);  // child own option
                            }
                        }
                    } else {
                        asn.object->set_option(rhs_fieldopt.option);  // asn own option
                    }
                }
                auto citer = index.find("Constraint");
                if (index.end() != citer) {
                    auto& rhs_cons = rhs[citer->second];
                    auto cons = rhs_cons.cons.u;
                    asn.object->get_constraints().add(cons);
                    if (asn1_entity_constraint_container != cons->get_entity()) rhs_cons.release();
                }
            }

            context.push(std::move(asn));

            return errorcode_t::success;
        });
    add_handler(
        "ComponentTypeList", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("ComponentTypeList", {"ComponentTypeList", ",", "ComponentType"})
            // production("ComponentTypeList", {"ComponentType"})

            auto size = node->sizeof_rhs();

            auto rhs_field = context.pop();
            if (1 == size) {
                auto container = new asn1_unknown_container;
                *container << rhs_field.object;

                asn1_semantic_node asn;
                asn.symbol = node->symbol;
                asn.object = container;

                rhs_field.release();  // container own object

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
    add_handler(
        "ExtensionAdditions", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t { return errorcode_t::success; });
    add_handler(
        "ComponentTypeLists", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("ComponentTypeLists", {"Constraint", "{", "ComponentTypeList", "ExtensionAdditions", "}"})
            // production("ComponentTypeLists", {"{", "ComponentTypeList", "ExtensionAdditions", "}"})
            // production("ComponentTypeLists", {"Constraint", "{", "ComponentTypeList", "}"})
            // production("ComponentTypeLists", {"{", "ComponentTypeList", "}"})
            // production("ComponentTypeLists", {"Constraint", "{", "}"})
            // production("ComponentTypeLists", {"{", "}"})

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            asn1_semantic_node asn;
            asn.symbol = node->symbol;

            auto iter = index.find("ComponentTypeList");
            if (index.end() != iter) {
                auto& rhs_fieldlist = rhs[iter->second];
                asn.object = rhs_fieldlist.object;
                rhs_fieldlist.release();  // asn own asn1_unknown_container
            }
            auto citer = index.find("Constraint");
            if (index.end() != citer) {
                auto& rhs_cons = rhs[citer->second];
                asn.cons = rhs_cons.cons;
                rhs_cons.release();  // asn own constraints
            }

            context.push(std::move(asn));

            return errorcode_t::success;
        });
    add_handler(
        "SequenceTypeSpec", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("SequenceTypeSpec", {"SEQUENCE", "ComponentTypeLists"})

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            asn1_semantic_node asn;
            auto sequence = new asn1_sequence;
            asn1_unknown_container* container = nullptr;
            auto& rhs_body = rhs[1];

            container = static_cast<asn1_unknown_container*>(rhs_body.object);
            if (container) sequence->set(*container);  // move

            auto cons = rhs_body.cons.u;
            if (cons) sequence->get_constraints().add(cons);

            rhs_body.release_option().release_constraint();  // rhs_body.object->release()

            asn.symbol = node->symbol;
            asn.object = sequence;
            context.push(std::move(asn));

            return errorcode_t::success;
        });
    add_handler(
        "SetTypeSpec", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("SetTypeSpec", {"SET", "ComponentTypeLists"})

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            asn1_semantic_node asn;
            auto set = new asn1_set;
            asn1_unknown_container* container = nullptr;
            auto& rhs_body = rhs[1];

            container = static_cast<asn1_unknown_container*>(rhs_body.object);
            if (container) set->set(*container);  // move

            auto cons = rhs_body.cons.u;
            if (cons) set->get_constraints().add(cons);

            rhs_body.release_option().release_constraint();  // rhs_body.object->release()

            asn.symbol = node->symbol;
            asn.object = set;
            context.push(std::move(asn));

            return errorcode_t::success;
        });
    add_handler(
        "ChoiceTypeSpec", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("ChoiceTypeSpec", {"CHOICE", "ComponentTypeLists"})

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            asn1_semantic_node asn;
            auto choice = new asn1_choice;
            asn1_unknown_container* container = nullptr;
            auto& rhs_body = rhs[1];

            container = static_cast<asn1_unknown_container*>(rhs_body.object);
            if (container) choice->set(*container);  // move

            auto cons = rhs_body.cons.u;
            if (cons) choice->get_constraints().add(cons);

            rhs_body.release_option().release_constraint();  // rhs_body.object->release()

            asn.symbol = node->symbol;
            asn.object = choice;
            context.push(std::move(asn));

            return errorcode_t::success;
        });
    add_handler(
        "SequenceOfTypeSpec", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("SequenceOfTypeSpec", {"SEQUENCE", "SizeConstraint", "OF", "Type"})
            // production("SequenceOfTypeSpec", {"SEQUENCE", "Constraint", "OF", "Type"})
            // production("SequenceOfTypeSpec", {"SEQUENCE", "OF", "Type"})

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            asn1_sequence_of* sequenceof = nullptr;

            auto iter = index.find("Type");
            if (index.end() != iter) {
                auto& rhs_typespec = rhs[iter->second];
                sequenceof = new asn1_sequence_of(rhs_typespec.object);
                rhs_typespec.release();
            }

            if (4 == size) {
                auto& rhs_cons = rhs[1];
                if ("SizeConstraint" == rhs_cons.symbol || "Constraint" == rhs_cons.symbol) {
                    auto cons = rhs_cons.cons.u;
                    sequenceof->get_constraints().add(cons);
                    if (asn1_entity_constraint_container != cons->get_entity()) rhs_cons.release();
                }
            }

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            asn.object = sequenceof;

            context.push(std::move(asn));

            return errorcode_t::success;
        });
    add_handler(
        "SetOfTypeSpec", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("SetOfTypeSpec", {"SET", "SizeConstraint", "OF", "Type"})
            // production("SetOfTypeSpec", {"SET", "Constraint", "OF", "Type"})
            // production("SetOfTypeSpec", {"SET", "OF", "Type"})

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            asn1_set_of* setof = nullptr;

            auto iter = index.find("Type");
            if (index.end() != iter) {
                auto& rhs_typespec = rhs[iter->second];
                setof = new asn1_set_of(rhs_typespec.object);
                rhs_typespec.release();
            }

            if (4 == size) {
                auto& rhs_cons = rhs[1];
                if ("SizeConstraint" == rhs_cons.symbol || "Constraint" == rhs_cons.symbol) {
                    auto cons = rhs_cons.cons.u;
                    setof->get_constraints().add(cons);
                    if (asn1_entity_constraint_container != cons->get_entity()) rhs_cons.release();
                }
            }

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            asn.object = setof;

            context.push(std::move(asn));

            return errorcode_t::success;
        });
    add_handler(
        "OptionalitySpec", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("OptionalitySpec", {"OPTIONAL"})
            // production("OptionalitySpec", {"DEFAULT", "ValueElement"})
            // production("OptionalitySpec", {"DEFAULT", "{", "}"})

            auto resource = asn1_resource::get_instance();

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            for (size_t i = 0; i < size; ++i) {
                rhs[size - 1 - i] = context.pop();
            }

            // auto parser_resource = parser_resource::get_instance();
            auto& rhs_type = rhs[0];

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            asn.option.type = resource->valueof_mode(rhs_type.symbol);
            if (2 == size) {
                auto& rhs_valueelem = rhs[1];  // ValueElement
                // variant v;
                // if (parser_resource->nameof(token_number) == rhs_valueelem.symbol) {
                //     v = t_atoi<asn1_native_int_t>(rhs_valueelem.value);
                // } else if (parser_resource->nameof(token_quot_string) == rhs_valueelem.symbol) {
                //     v = rhs_valueelem.value;
                // }
                // asn.option.defvalue = new asn1_default_t(std::move(v.get()));
                asn.option.defvalue = new asn1_default_t(std::move(rhs_valueelem.v.get()));
            }

            context.push(std::move(asn));

            return errorcode_t::success;
        });
    // ActualParameterList
    // ActualParameter
    add_handler(
        "TaggedTypeSpec", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("TaggedTypeSpec", {"TagSpec", "IMPLICIT", "Type"})
            // production("TaggedTypeSpec", {"TagSpec", "EXPLICIT", "Type"})
            // production("TaggedTypeSpec", {"TagSpec", "Type"})

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
    add_handler(
        "TagSpec", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("TagSpec", {"[", "TagClass", symnum, "]"})
            // production("TagSpec", {"[", symnum, "]"})

            auto size = node->sizeof_rhs();  // 3 or 4

            context.pop();                            // ]
            auto tagnum = context.pop();              // number
            asn1_semantic_node tagclass;              // CONTEXT
            if (4 == size) tagclass = context.pop();  // UNIVERSAL, APPLICATION, PRIVATE
            context.pop();                            // [

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            asn.object = asn1_builder::buildtag(tagclass.value, atol(tagnum.value.c_str()));

            context.push(std::move(asn));

            return errorcode_t::success;
        });
    add_handler(
        "EnumeratedType", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            for (size_t i = 0; i < size; ++i) {
                rhs[size - 1 - i] = context.pop();
            }

            auto& rhs_simpletype = rhs[0];
            auto& rhs_enumlist = rhs[2];

            // auto entity = resource->get_entity(rhs_simpletype.symbol);  // ENUMBERATED
            auto container = static_cast<asn1_namedlist*>(rhs_enumlist.object);

            auto obj = new asn1_enum;
            obj->add(*container);

            asn1_semantic_node asn(std::move(rhs_simpletype));
            asn.object = obj;
            asn.symbol = node->symbol;

            context.push(std::move(asn));

            return errorcode_t::success;
        });
    // ExtensionAdditionEnumeration
    add_handler(
        "Enumerations", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("Enumerations", {"Enumerations", ",", "Enumeration"})
            // production("Enumerations", {"Enumeration"})

            auto size = node->sizeof_rhs();

            auto rhs_enumitem = context.pop();
            if (1 == size) {
                asn1_semantic_node asn(std::move(rhs_enumitem));
                asn.symbol = node->symbol;
                context.push(std::move(asn));
            } else if (3 == size) {
                context.pop();  // ","
                auto rhs_enumlist = context.pop();

                auto item_container = static_cast<asn1_namedlist*>(rhs_enumitem.object);
                auto container = static_cast<asn1_namedlist*>(rhs_enumlist.object);
                container->add(*item_container);

                asn1_semantic_node asn;
                asn.symbol = node->symbol;
                asn.object = container;

                rhs_enumlist.release();  // asn own container

                context.push(std::move(asn));
            }

            return errorcode_t::success;
        });
    add_handler(
        "Enumeration", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("Enumeration", {symid, "(", symnum, ")"})

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            for (size_t i = 0; i < size; ++i) {
                rhs[size - 1 - i] = context.pop();
            }

            auto& rhs_symid = rhs[0];
            auto& rhs_symnum = rhs[2];

            auto container = new asn1_namedlist;
            container->add(rhs_symid.value, atol(rhs_symnum.value.c_str()));

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            asn.object = container;
            context.push(std::move(asn));

            return errorcode_t::success;
        });
    // ExtensionMarker
    add_handler(
        "SimpleTypeSpec", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            auto resource = asn1_resource::get_instance();

            auto size = node->sizeof_rhs();  // 1, 4
            std::vector<asn1_semantic_node> rhs(size);
            for (size_t i = 0; i < size; ++i) {
                rhs[size - 1 - i] = context.pop();
            }

            auto& rhs_simpletype = rhs[0];
            auto entity = resource->get_entity(rhs_simpletype.symbol);  // BOOLEAN, ..., ANY

            auto obj = asn1_builder::build(entity);
            if (4 == size) {
                // production("SimpleTypeSpec", {"INTEGER", "{", "Enumerations", "}"})
                // production("SimpleTypeSpec", {"BIT STRING", "{", "Enumerations", "}"})
                auto& rhs_enumlist = rhs[2];
                auto container = static_cast<asn1_namedlist*>(rhs_enumlist.object);
                if ("INTEGER" == rhs_simpletype.symbol) ((asn1_integer*)obj)->add(*container);
                if ("BIT STRING" == rhs_simpletype.symbol) ((asn1_bitstring*)obj)->add(*container);
            }

            asn1_semantic_node asn(std::move(rhs_simpletype));
            asn.object = obj;
            asn.symbol = node->symbol;

            context.push(std::move(asn));

            return errorcode_t::success;
        });
    // ObjectClassAssignment
    // FieldList
    // Field
    // SyntaxList
    // SyntaxItem
    // ObjectClassFieldType
    // ClassFieldReference
    // InformationObjectAssignment
    // SettingList
    // SettingItem
    add_handler(
        "ValueElement", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("ValueElement", {symqs})
            // production("ValueElement", {"MIN"})
            // production("ValueElement", {"MAX"})
            // production("ValueElement", {"TRUE"})
            // production("ValueElement", {"FALSE"})
            // production("ValueElement", {symnum})
            // production("ValueElement", {symfp})

            auto rhs_valueelem = context.pop();

            auto pr = parser_resource::get_instance();
            auto symqs = pr->nameof(token_quot_string);
            auto symnum = pr->nameof(token_number);
            auto symfp = pr->nameof(token_floatingpoint);

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            if (symqs == rhs_valueelem.symbol) {
                std::string& qs = rhs_valueelem.value;
                if (false == qs.empty()) qs.erase(qs.begin());
                if (false == qs.empty()) qs.pop_back();
                asn.v.set_string(qs);
            } else if (symnum == rhs_valueelem.symbol) {
                asn.v.set(t_atoi<asn1_native_int_t>(rhs_valueelem.value));
            } else if (symfp == rhs_valueelem.symbol) {
                asn.v.set(atof(rhs_valueelem.value.c_str()));
            } else if ("MIN" == rhs_valueelem.symbol) {
                asn.v = variant::minvalue();
            } else if ("MAX" == rhs_valueelem.symbol) {
                asn.v = variant::maxvalue();
            }

            context.push(std::move(asn));

            return errorcode_t::success;
        });
}

return_t asn1_publisher::default_handler(parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) {
    return_t ret = errorcode_t::success;

    // pop and push
    // simply modify top

    auto& top = context.top();
    top.symbol = node->symbol;

    return ret;
}

}  // namespace io
}  // namespace hotplace
