/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_module.cpp
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

asn1_module::asn1_module() { _shared.make_share(this); }

asn1_module::asn1_module(const std::string& name) : asn1_module() { _name = name; }

asn1_module::asn1_module(const asn1_module& other) : asn1_module() { *this = other; }

asn1_module::asn1_module(asn1_module&& other) : asn1_module() { *this = std::move(other); }

asn1_module::~asn1_module() { clear(); }

asn1_module& asn1_module::operator=(const asn1_module& other) {
    critical_section_guard outer_guard(other._lock);
    critical_section_guard inner_guard(_lock);

    for (const auto& item : other._types) {
        auto type = item->clone();

        add(type);

        auto value = other.get(item);
        if (value) {
            _values.emplace(type, new asn1_value(*value));
        }
    }

    _exports = other._exports;
    _imports = other._imports;

    return *this;
}

asn1_module& asn1_module::operator=(asn1_module&& other) {
    critical_section_guard outer_guard(other._lock);
    critical_section_guard inner_guard(_lock);

    _dictionary = std::move(other._dictionary);
    _types = std::move(other._types);
    _values = std::move(other._values);
    _schema = std::move(other._schema);

    std::swap(_tagdefault, other._tagdefault);
    std::swap(_extensibility, other._extensibility);
    std::swap(_is_module, other._is_module);

    _exports = std::move(other._exports);
    _imports = std::move(other._imports);

    return *this;
}

asn1_module* asn1_module::clone() { return new asn1_module(*this); }

return_t asn1_module::add_schema(const std::string& schema) {
    return_t ret = errorcode_t::success;

    // parse
    asn1_parser parser(parser_type_t::glr, true);
    parse_tree pt;
    parser.parse(schema.c_str(), &pt);

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

    auto publisher = asn1_advisor::get_instance()->get_publisher();
    asn1_build_resultset result;
    ret = publisher->build(&pt, result);
    if (errorcode_t::success != ret) return ret;

    auto object = result.object;

    critical_section_guard guard(_lock);
    auto pib = _schema.emplace(object, schema);
    if (false == pib.second) return errorcode_t::already_exist;

    object->addref();  // this own object
    return add(object);
}

return_t asn1_module::add(asn1_object* item) {
    if (nullptr == item) return errorcode_t::invalid_parameter;

    critical_section_guard guard(_lock);

    _types.push_back(item);

    const std::string& name = item->get_name();
    if (false == name.empty()) {
        _dictionary.emplace(name, item);
    }

    return errorcode_t::success;
}

asn1_module& asn1_module::operator<<(const std::string& schema) {
    add_schema(schema);
    return *this;
}

asn1_module& asn1_module::operator<<(asn1_object* item) {
    add(item);
    return *this;
}

return_t asn1_module::set(asn1_object* item, asn1_value* value) {
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

asn1_object* asn1_module::get(const std::string& name) const {
    asn1_object* ret_value = nullptr;
    critical_section_guard guard(_lock);
    if (name.empty() && (1 == _types.size())) {
        ret_value = *_types.begin();
    } else {
        auto iter = _dictionary.find(name);
        if (_dictionary.end() == iter) {
            auto modules = asn1_modules::get_instance();
            for (const auto& module : _imports) {
                for (const auto& symbol : module.symbols) {
                    if (symbol == name) {
                        auto outer = modules->get(module.outer_module);
                        if (outer) {
                            ret_value = outer->get(symbol);
                        }
                        break;
                    }
                }
            }
        } else {
            ret_value = iter->second;
        }
    }
    return ret_value;
}

asn1_value* asn1_module::get(asn1_object* item) const {
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

return_t asn1_module::read_weakly_typed(const byte_t* stream, size_t size, size_t& pos) {
    asn1_weakly_typed weaktype;
    return weaktype.read(this, stream, size, pos);
}

return_t asn1_module::read(const std::string& name, const byte_t* stream, size_t size, size_t& pos) {
    asn1_strongly_typed strongtype;
    return strongtype.read(this, name, stream, size, pos);
}

return_t asn1_module::update_linkage(asn1_object* object) {
    if (nullptr == object) return errorcode_t::invalid_parameter;

    auto entity = object->get_entity();
    switch (entity) {
        case asn1_entity_tagged_type: {
            auto tagtype = (asn1_tagged_type*)object;
            tagtype->update_linkage(this);
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

void asn1_module::for_each(std::function<void(asn1_object*)> f) const {
    for (const auto& item : _types) {
        f(item);
    }
}

void asn1_module::for_each(std::function<void(asn1_value*)> f) const {
    for (const auto& pair : _values) {
        f(pair.second);
    }
}

void asn1_module::represent(stream_t* s) {
    auto advisor = asn1_advisor::get_instance();
    asn1_notation_visitor notation(s);
    if (_is_module) {
        // ... DEFINITIONS ... ::= BEGIN
        // TODO OID
        s->printf("%s %s", _name.c_str(), "DEFINITIONS ");
        if (asn1_tagdefault != _tagdefault) s->printf("%s TAGS ", advisor->nameof_mode(_tagdefault, true).c_str());
        if (_extensibility) {
            s->printf("EXTENSIBILITY IMPLIED ");
        }
        s->printf("::= BEGIN\n");

        // EXPORTS
        if (asn1_exports_t::all == _exports.type) {
            s->printf("EXPORTS ALL\n");
        }
        if ((asn1_exports_t::list == _exports.type) && (false == _exports.symbols.empty())) {
            s->printf("EXPORTS ");
            auto size = _exports.symbols.size();
            for (size_t i = 0; i < size; ++i) {
                if (0 != i) s->printf(", ");
                s->printf("%s", _exports.symbols[i].c_str());
            }
            s->printf(";\n");
        }
        // IMPORTS
        if (false == _imports.empty()) {
            for (auto iter = _imports.begin(); iter != _imports.end(); ++iter) {
                const auto& symbol_module = *iter;
                const auto& outer_module = symbol_module.outer_module;
                const auto& symbols = symbol_module.symbols;
                s->printf("IMPORTS ");
                size_t idx = 0;
                for (auto symiter = symbols.begin(); symiter != symbols.end(); ++symiter, ++idx) {
                    if (0 != idx) s->printf(", ");
                    s->printf("%s", (*symiter).c_str());
                }
                s->printf(" FROM %s;\n", outer_module.c_str());
            }
        }
    }
    auto nl = _types.size() > 1;
    for (const auto& item : _types) {
        notation.visit(item);
        if (nl) s->printf("\n");
    }
    if (_is_module) {
        if (false == nl) s->printf("\n");
        s->printf("END\n");
    }
}

void asn1_module::publish(stream_t* s) {
    auto nl = _types.size() > 1;
    for (const auto& pair : _values) {
        auto value = pair.second;
        asn1_notation_visitor notation(s, value);
        notation.visit(value->get_schema());
        if (nl) s->printf("\n");
    }
}

void asn1_module::publish(binary_t* b) {
    for (const auto& pair : _values) {
        auto value = pair.second;
        asn1_der_visitor encoder(b, this, value);
        encoder.visit(value->get_schema());
    }
}

void asn1_module::represent(const std::string& name, stream_t* s) {
    auto schema = get(name);
    if (nullptr == schema) return;

    asn1_notation_visitor notation(s);
    notation.visit(schema);
}

void asn1_module::publish(const std::string& name, stream_t* s) {
    auto schema = get(name);
    if (nullptr == schema) return;

    auto value = get(schema);
    if (nullptr == value) return;

    asn1_notation_visitor notation(s, value);
    notation.visit(value->get_schema());
}

void asn1_module::publish(const std::string& name, binary_t* b) {
    auto schema = get(name);
    if (nullptr == schema) return;

    auto value = get(schema);
    if (nullptr == value) return;

    asn1_der_visitor encoder(b, this, value);
    encoder.visit(schema);
}

void asn1_module::set_name(const std::string& name) { _name = name; }

std::string asn1_module::get_name() { return _name; }

void asn1_module::set_tagdefault(uint8 value) { _tagdefault = value; }

uint8 asn1_module::get_tagdefault() { return _tagdefault; }

void asn1_module::set_extensibility(uint8 value) { _extensibility = value; }

uint8 asn1_module::get_extensibility() { return _extensibility; }

void asn1_module::clear() {
    for (auto& item : _types) item->release();
    for (auto& pair : _values) pair.second->release();
    _types.clear();
    _values.clear();
    _schema.clear();
    _exports.clear();
    _imports.clear();
}

void asn1_module::addref() { _shared.addref(); }

void asn1_module::release() { _shared.delref(); }

}  // namespace io
}  // namespace hotplace
