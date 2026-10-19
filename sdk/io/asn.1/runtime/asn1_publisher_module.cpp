/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_publisher_module.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *   Considerations for `asn1_modules` in a multi-threaded environment:
 *   - Whenever possible, use `add` and `get` operations that do not modify the current pointer.
 */

#include <hotplace/sdk/io/asn.1/asn1_advisor.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_module.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_modules.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_publisher.hpp>
#include <hotplace/sdk/io/parser/parse_tree.hpp>

namespace hotplace {
namespace io {

void asn1_publisher::prepare_module() {
    // Start
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

            auto modules = asn1_modules::get_instance();

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
            auto module = modules->add(module_id);

            result.type = asn1_build_t::module_definition;
            result.module_names.push_back(module_id);

            context.get_runtime().as_module();  // as module

            auto rtmodule = modules->add(module_id);
            *rtmodule = std::move(context.get_runtime());

            auto iter = index.find("TagDefault");
            if (index.end() != iter) {
                auto& rhs_tagdefault = rhs[iter->second];
                asn.module.tagdefault = rhs_tagdefault.module.tagdefault;
                module->set_tagdefault(asn.module.tagdefault);
            } else {
                module->set_tagdefault(asn1_tagdefault);  // MyModule DEFINITIONS ::= BEGIN ...
            }
            iter = index.find("ExtensionDefault");
            if (index.end() != iter) {
                auto& rhs_ext = rhs[iter->second];
                asn.module.extensibility = rhs_ext.module.extensibility;
                module->set_extensibility(uint8(asn.module.extensibility));
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
}

}  // namespace io
}  // namespace hotplace
