/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_runtime.cpp
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
#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_referenced_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tagged_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_der_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_notation_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_visitor.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_builder.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_publisher.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_strongly_typed.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_weakly_typed.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>

namespace hotplace {
namespace io {

asn1_runtime::asn1_runtime() {
    _shared.make_share(this);
    _automatic = asn1_explicit;
}

asn1_runtime::asn1_runtime(const std::string& name) : asn1_runtime() { _name = name; }

asn1_runtime::asn1_runtime(const asn1_runtime& other) : asn1_runtime() { *this = other; }

asn1_runtime::~asn1_runtime() { clear(); }

asn1_runtime& asn1_runtime::operator=(const asn1_runtime& other) {
    critical_section_guard guard(_lock);

    for (const auto& item : other._types) {
        auto type = item->clone();

        add(type);

        auto value = other.get(item);
        if (value) {
            _values.emplace(type, new asn1_value(*value));
        }
    }
    return *this;
}

asn1_runtime* asn1_runtime::clone() { return new asn1_runtime(*this); }

void asn1_runtime::load() {
    if (false == get_parser().ready()) {
        auto& lex = get_lexer();
        // handle_quoted to 1
        lex.get_config().set("handle_comments", 1).set("handle_quoted", 1).set("handle_token", 1).set("handle_lvalue_usertype", 1);
        lex.prepare();

        // ASN.1 tokens
        auto resource = parser_resource::get_instance();
        resource->for_each(resource_type_t::token_type_asn1, [&lex](uint32 token, const std::string& name) -> void { lex.add_token(name, token); });

        /*
        // CFG - production, terminal, non-terminal, start symbol
        cfg_grammar grammar;
        for (const auto& item : asn1_notation_productions) {
            grammar.add_production(item.lhs, item.rhs);
        }
        for (const auto& item : asn1_notation_terminals) {
            grammar.add_terminal(item);
        }

        get_parser().set_grammar(std::move(grammar));

        get_parser().learn();  // heavy
        */

        get_parser().import(asn1_notation_productions, asn1_notation_action_table, asn1_notation_goto_table);
    }
}

return_t asn1_runtime::add_schema(const std::string& schema) {
    return_t ret = errorcode_t::success;

    // parse
    parse_tree pt;
    parse(schema.c_str(), &pt);

#if defined DEBUG
    if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
        trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
            uint32 idx = 0;
            auto lambda = [&idx, &dbs](parser_action_t type, parse_treenode* node) -> return_t {
                valist va;
                va << idx++ << node->symbol << node->value << node->children.size();
                dbs.vaprintf("[{1:03i}] ", va);
                switch (type) {
                    case parser_action_t::shift:
                        dbs << "shift  ";
                        break;
                    case parser_action_t::reduce:
                        dbs << "reduce ";
                        break;
                    default:
                        break;
                }
                dbs.vaprintf("{2}", va);
                if ((false == node->value.empty()) && (node->symbol != node->value)) {
                    dbs.vaprintf(" ({3})", va);
                }
                if (parser_action_t::reduce == type) {
                    dbs.vaprintf(" RHS [{4}]", va);
                }
                dbs << "\n";

                return errorcode_t::success;
            };
            parse_tree_visitor visitor(lambda);
            pt.accept(&visitor);
        });
    }
#endif

    // reconstruction
    basic_stream bs;
    asn1_object* object = nullptr;

    asn1_publisher publisher;
    ret = publisher.build(this, &pt, &object);
    if (errorcode_t::success != ret) return ret;

    critical_section_guard guard(_lock);
    auto pib = _schema.emplace(object, schema);
    if (false == pib.second) return errorcode_t::already_exist;

    return add(object);
}

return_t asn1_runtime::add(asn1_object* item) {
    if (nullptr == item) return errorcode_t::invalid_parameter;

    critical_section_guard guard(_lock);

    _types.push_back(item);

    const std::string& name = item->get_name();
    if (false == name.empty()) {
        _dictionary.emplace(name, item);
    }

    return errorcode_t::success;
}

asn1_runtime& asn1_runtime::operator<<(const std::string& schema) {
    add_schema(schema);
    return *this;
}

asn1_runtime& asn1_runtime::operator<<(asn1_object* item) {
    add(item);
    return *this;
}

return_t asn1_runtime::set(asn1_object* item, asn1_value* value) {
    return_t ret = errorcode_t::success;
    if (item && value) {
        critical_section_guard guard(_lock);
        auto pib = _values.emplace(item, value);
        if (false == pib.second) {
            ret = errorcode_t::already_exist;
        }
    } else
        ret = errorcode_t::invalid_parameter;
    return ret;
}

asn1_object* asn1_runtime::get(const std::string& name) const {
    asn1_object* ret_value = nullptr;
    critical_section_guard guard(_lock);
    if (name.empty() && (1 == _types.size())) {
        ret_value = *_types.begin();
    } else {
        auto iter = _dictionary.find(name);
        if (_dictionary.end() != iter) {
            ret_value = iter->second;
        }
    }
    return ret_value;
}

asn1_value* asn1_runtime::get(asn1_object* item) const {
    asn1_value* ret_value = nullptr;
    if (item) {
        critical_section_guard guard(_lock);
        auto iter = _values.find(item);
        if (_values.end() != iter) {
            ret_value = iter->second;
        }
    }
    return ret_value;
}

lexical_analyzer& asn1_runtime::get_lexer() { return _lex; }

lalr_parser& asn1_runtime::get_parser() { return _lalr; }

return_t asn1_runtime::read_weakly_typed(const byte_t* stream, size_t size, size_t& pos) {
    asn1_weakly_typed weaktype;
    return weaktype.read(this, stream, size, pos);
}

return_t asn1_runtime::read(const std::string& name, const byte_t* stream, size_t size, size_t& pos) {
    asn1_strongly_typed strongtype;
    return strongtype.read(this, name, stream, size, pos);
}

return_t asn1_runtime::parse(const char* notation, parse_tree* pt) {
    return_t ret = errorcode_t::success;
    __try2 {
        load();

        if (nullptr == notation) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = get_lexer().parse(_lexcontext, notation);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // LALR tokens
        std::vector<parser_token> tokens;
#if defined DEBUG
        uint32 cnt = 0;
#endif

        auto resource = parser_resource::get_instance();
        auto symid = resource->nameof(token_identifier);  // "identifier"
        auto symuser = resource->nameof(token_usertype);  // "usertype"

        auto lambda = [&](const token_description* desc) -> bool {
            bool test = true;
            const auto& type = desc->type;
            std::string token(desc->p, desc->size);
            switch (type) {
                case token_lvalue: {
                    tokens.push_back({token_identifier, symid});
                } break;
                case token_comments:
                    ret = false;  // stop at comments
                    break;
                default: {
                    tokens.push_back({type, token});
                }
            }

#if defined DEBUG
            if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
                trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                    dbs.println("[%03u] line %zi type %d(%s) index %d pos %zi len %zi (%.*s)", cnt++, desc->line, desc->type,
                                get_lexer().nameof_token(desc->type).c_str(), desc->index, desc->pos, desc->size, (unsigned)desc->size, desc->p);
                });
            }
#endif

            return test;
        };
        _lexcontext.for_each(lambda);
        tokens.push_back({token_eof, "$"});

        // LALR(1) parse
        ret = get_parser().parse(tokens, pt);
    }
    __finally2 {}
    return ret;
}

bool asn1_runtime::resolve(const std::string& name, std::list<std::string>& names) const {
    names.clear();

    if (_dictionary.end() == _dictionary.find(name)) {
        return false;
    }

    // 1. collect only relevant sub-dependency nodes starting from 'name'
    std::set<std::string> sub_nodes;
    std::queue<std::string> q;

    q.push(name);
    sub_nodes.insert(name);

    bool missing_reference = false;

    while (false == q.empty()) {
        std::string current = std::move(q.front());
        q.pop();

        auto iter = _dictionary.find(current);
        if (_dictionary.end() == iter || nullptr == iter->second) {
            missing_reference = true;
            break;
        }

        auto lambda = [&](asn1_object* sub_item) -> void {
            if (nullptr != sub_item && asn1_entity_referenced_type == sub_item->get_entity()) {
                auto ref = static_cast<asn1_referenced_type*>(sub_item);
                if (ref->is_reference()) {
                    const std::string& ref_name = ref->get_reference();

                    // Check if referenced type exists in dictionary
                    if (_dictionary.end() == _dictionary.find(ref_name)) {
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
        visitor.visit(iter->second);

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

bool asn1_runtime::resolve(std::list<std::string>& names) const {
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
                    if (_dictionary.end() == _dictionary.find(ref_name)) {
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

bool asn1_runtime::is_resolvable(const std::string& name) const {
    std::list<std::string> resolved_names;
    return resolve(name, resolved_names);
}

bool asn1_runtime::is_resolvable(asn1_object* object) const {
    if (nullptr == object) return false;
    return is_resolvable(object->get_name());
}

bool asn1_runtime::is_resolvable() const {
    std::list<std::string> names;
    return resolve(names);
}

return_t asn1_runtime::update_linkage(asn1_object* object) {
    if (nullptr == object) return errorcode_t::invalid_parameter;

    auto entity = object->get_entity();
    switch (entity) {
        case asn1_entity_tagged_type: {
            auto tagtype = (asn1_tagged_type*)object;
            tagtype->update_linkage();
        } break;
        case asn1_entity_referenced_type: {
            auto ref = (asn1_referenced_type*)object;
            if (ref->is_reference()) {
                if (nullptr == ref->get_object()) {
                    auto schema = get(ref->get_reference());
                    if (nullptr == schema) return errorcode_t::not_found;
                    auto clone = schema->clone();
                    ref->set_object(clone);
                }
                auto parent = object->get_parent();  // asn1_entity_tagged_type
                if (parent)
                    update_linkage(parent);  // constructed bit/explicit propagation
                else
                    update_linkage(ref->get_object());
            }
        } break;
        default: {
        } break;
    }
    return errorcode_t::success;
}

void asn1_runtime::for_each(std::function<void(asn1_object*)> f) const {
    for (const auto& item : _types) {
        f(item);
    }
}

void asn1_runtime::for_each(std::function<void(asn1_value*)> f) const {
    for (const auto& pair : _values) {
        f(pair.second);
    }
}

void asn1_runtime::notation(stream_t* s) {
    asn1_notation_visitor notation(s);
    auto nl = _types.size() > 1;
    for (const auto& item : _types) {
        notation.visit(item);
        if (nl) s->printf("\n");
    }
}

void asn1_runtime::publish(stream_t* s) {
    auto nl = _types.size() > 1;
    for (const auto& pair : _values) {
        auto value = pair.second;
        asn1_notation_visitor notation(s, value);
        notation.visit(value->get_schema());
        if (nl) s->printf("\n");
    }
}

void asn1_runtime::publish(binary_t* b) {
    for (const auto& pair : _values) {
        auto value = pair.second;
        asn1_der_visitor encoder(b, this, value);
        encoder.visit(value->get_schema());
    }
}

void asn1_runtime::notation(const std::string& name, stream_t* s) {
    auto schema = get(name);
    if (nullptr == schema) return;

    asn1_notation_visitor notation(s);
    notation.visit(schema);
}

void asn1_runtime::publish(const std::string& name, stream_t* s) {
    auto schema = get(name);
    if (nullptr == schema) return;

    auto value = get(schema);
    if (nullptr == value) return;

    asn1_notation_visitor notation(s, value);
    notation.visit(value->get_schema());
}

void asn1_runtime::publish(const std::string& name, binary_t* b) {
    auto schema = get(name);
    if (nullptr == schema) return;

    auto value = get(schema);
    if (nullptr == value) return;

    asn1_der_visitor encoder(b, this, value);
    encoder.visit(schema);
}

void asn1_runtime::set_name(const std::string& name) { _name = name; }

std::string asn1_runtime::get_name() { return _name; }

void asn1_runtime::set_automatic(uint8 runas) { _automatic = runas; }

uint8 asn1_runtime::runas_automatic() { return _automatic; }

void asn1_runtime::clear() {
    for (auto& item : _types) item->release();
    for (auto& pair : _values) pair.second->release();
    _types.clear();
    _values.clear();
    _schema.clear();
}

void asn1_runtime::addref() { _shared.addref(); }

void asn1_runtime::release() { _shared.delref(); }

}  // namespace io
}  // namespace hotplace
