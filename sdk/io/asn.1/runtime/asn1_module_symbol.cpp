/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_module_symbol.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026.09.14   Soo Han and Gemini  resolve, is_resolvable
 *
 */

#include <hotplace/sdk/base/basic/valist.hpp>
#include <hotplace/sdk/base/graph/graph.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/asn.1/asn1_advisor.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_referenced_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tagged_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_der_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_notation_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_visitor.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_module.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_modules.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_parser.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_strongly_typed.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_weakly_typed.hpp>

namespace hotplace {
namespace io {

asn1_object* asn1_module::search(const std::string& name) const {
    critical_section_guard guard(_lock);

    auto iter = _dictionary.find(name);
    if (_dictionary.end() != iter) {
        return iter->second;
    }

    if (false == _imports.empty()) {
        auto modules = asn1_modules::get_instance();
        for (const auto& module : _imports) {
            for (const auto& symbol : module.symbols) {
                if (symbol == name) {
                    auto outer = modules->get(module.outer_module);
                    if (outer) {
                        auto obj = outer->search_by_symbol(name);
                        if (obj) {
                            return obj;
                        }
                    }
                    break;
                }
            }
        }
    }

    return nullptr;
}

asn1_object* asn1_module::search_by_symbol(const std::string& name) const {
    critical_section_guard guard(_lock);

    auto iter = _dictionary.find(name);
    if (_dictionary.end() == iter) {
        return nullptr;
    }

    auto type = _exports.type;

    if (asn1_exports_t::all == type) {
        // EXPORTS clause is omitted
        // EXPORTS ALL
        return iter->second;
    } else if (asn1_exports_t::list == type) {
        // explicit EXPORTS clause
        for (const auto& symbol : _exports.symbols) {
            if (symbol == name) {
                return iter->second;
            }
        }
    }

    return nullptr;
}

bool asn1_module::resolve(const std::string& name, std::list<std::string>& names) const {
    names.clear();

    if (nullptr == search(name)) return false;

    // 1. collect only relevant sub-dependency nodes starting from 'name'
    std::set<std::string> sub_nodes;
    std::queue<std::string> q;

    q.push(name);
    sub_nodes.insert(name);

    bool missing_reference = false;

    while (false == q.empty()) {
        std::string current = std::move(q.front());
        q.pop();

        auto current_obj = search(current);
        if (nullptr == current_obj) {
            missing_reference = true;
            break;
        }

        auto lambda = [&](asn1_object* sub_item) -> void {
            if (nullptr != sub_item && asn1_entity_referenced_type == sub_item->get_entity()) {
                auto ref = static_cast<asn1_referenced_type*>(sub_item);
                if (ref->is_reference()) {
                    const std::string& ref_name = ref->get_reference();

                    // Check if referenced type exists in dictionary
                    auto ref_obj = search(ref_name);
                    if (nullptr == ref_obj) {
                        missing_reference = true;
                        return;
                    }

                    if (sub_nodes.end() == sub_nodes.find(ref_name)) {
                        sub_nodes.insert(ref_name);
                        q.push(ref_name);
                    }
                }
            }
        };

        asn1_visitor visitor(this, lambda);
        visitor.visit(current_obj);

        if (true == missing_reference) {
            break;
        }
    }

    if (true == missing_reference) {
        return false;
    }

    // 2. build local sub-graph
    t_graph<std::string> sub_graph;

    for (const auto& node_name : sub_nodes) {
        asn1_object* object = _dictionary.at(node_name);

        auto lambda = [&](asn1_object* sub_item) -> void {
            if (nullptr != sub_item && asn1_entity_referenced_type == sub_item->get_entity()) {
                auto ref = static_cast<asn1_referenced_type*>(sub_item);
                if (ref->is_reference()) {
                    const std::string& ref_name = ref->get_reference();
                    if (sub_nodes.end() != sub_nodes.find(ref_name) && node_name != ref_name) {
                        sub_graph.add_directed_edge(ref_name, node_name);
                    }
                }
            }
        };

        asn1_visitor visitor(this, lambda);
        visitor.visit(object);
    }

    // 3. perform topological sort for local sub-graph
    return sub_graph.topological_sort(names);
}

bool asn1_module::resolve(std::list<std::string>& names) const {
    names.clear();

    if (true == _dictionary.empty()) {
        return true;
    }

    t_graph<std::string> graph;

    bool missing_reference = false;

    // build graph edges
    for (const auto& item : _dictionary) {
        const std::string& type_name = item.first;
        asn1_object* object = item.second;

        if (nullptr == object) {
            return false;
        }

        auto lambda = [&](asn1_object* sub_item) -> void {
            if (nullptr != sub_item && asn1_entity_referenced_type == sub_item->get_entity()) {
                auto ref = static_cast<asn1_referenced_type*>(sub_item);
                if (ref->is_reference()) {
                    const std::string& ref_name = ref->get_reference();

                    // check if referenced type exists in dictionary
                    auto ref_obj = search(ref_name);
                    if (nullptr == ref_obj) {
                        missing_reference = true;
                        return;
                    }

                    if (type_name != ref_name) {
                        graph.add_directed_edge(ref_name, type_name);
                    }
                }
            }
        };

        asn1_visitor visitor(this, lambda);
        visitor.visit(object);

        if (true == missing_reference) {
            return false;
        }
    }

    // delegate topological sort and cycle check to t_graph
    return graph.topological_sort(names);
}

bool asn1_module::is_resolvable(const std::string& name) const {
    std::list<std::string> resolved_names;
    return resolve(name, resolved_names);
}

bool asn1_module::is_resolvable(asn1_object* object) const {
    if (nullptr == object) return false;
    return is_resolvable(object->get_name());
}

bool asn1_module::is_resolvable() const {
    std::list<std::string> names;
    return resolve(names);
}

asn1_module& asn1_module::as_module() {
    _is_module = true;
    return *this;
}

bool asn1_module::is_module() const { return _is_module; }

asn1_module& asn1_module::export_symbol(const asn1_exports& exports) {
    _exports = exports;
    return *this;
}

asn1_module& asn1_module::export_symbol(asn1_exports&& exports) {
    _exports = std::move(exports);
    return *this;
}

asn1_module& asn1_module::import_symbol(const asn1_symbol_module& symbol_module) {
    _imports.push_back(symbol_module);
    return *this;
}

asn1_module& asn1_module::import_symbol(asn1_symbol_module&& symbol_module) {
    _imports.push_back(std::move(symbol_module));
    return *this;
}

const asn1_exports& asn1_module::get_exports() const { return _exports; }

const std::list<asn1_symbol_module>& asn1_module::get_imports() const { return _imports; }

}  // namespace io
}  // namespace hotplace
