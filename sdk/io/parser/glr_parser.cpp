/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   glr_parser.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc   Generalized LR (GLR) parser implementation with GSS support
 *
 * Revision History
 * Date         Name                Description
 * 2026.09.22   Soo Han and Gemini  study
 *
 */

#include <hotplace/sdk/base/nostd/utility.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/parser/binary_parsing_table.hpp>
#include <hotplace/sdk/io/parser/cfg_grammar.hpp>
#include <hotplace/sdk/io/parser/glr_parser.hpp>
#include <iomanip>
#include <iostream>
#include <list>
#include <queue>

namespace hotplace {
namespace io {

glr_parser::glr_parser() : _is_table_built(false) { _shared.make_share(this); }

glr_parser::glr_parser(const cfg_grammar& g) : glr_parser() { _grammar = g; }

glr_parser::glr_parser(cfg_grammar&& g) : glr_parser() { _grammar = std::move(g); }

glr_parser::~glr_parser() {}

void glr_parser::set_grammar(const cfg_grammar& g) {
    critical_section_guard guard(_lock);
    _grammar = g;
    _is_table_built = false;
}

void glr_parser::set_grammar(cfg_grammar&& g) {
    critical_section_guard guard(_lock);
    _grammar = std::move(g);
    _is_table_built = false;
}

const cfg_grammar& glr_parser::get_cfg_grammar() const { return _grammar; }

cfg_grammar& glr_parser::get_cfg_grammar() { return _grammar; }

bool glr_parser::ready() const {
    critical_section_guard guard(_lock);
    return _is_table_built;
}

void glr_parser::clear() {
    critical_section_guard guard(_lock);
    _is_table_built = false;
    _is_imported = false;
    _context.clear();
    _action_table.clear();
    _goto_table.clear();
}

return_t glr_parser::learn() {
    return_t ret = errorcode_t::success;

    critical_section_guard guard(_lock);
    __try2 {
        compute_first_and_follow_sets(_grammar, _context);
        build_lr0_states(_grammar, _context, _goto_table);

        if (false == generate_glr_tables(_grammar, _context, _goto_table, _action_table)) {
            _is_table_built = false;
            ret = errorcode_t::not_ready;
            __leave2;
        }

#if defined DEBUG
        if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_debug)) {
            trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                print_style_t style("{", ", ", "}", 2);

                auto lambda_goto = [](typename std::map<std::pair<uint32, std::string>, uint32>::const_iterator it, basic_stream& dbs) -> void {
                    dbs << "{" << it->first.first << ", \"" << it->first.second << "\"}, " << it->second;
                };

                auto lambda_action = [](typename std::multimap<std::pair<uint32, std::string>, parser_action_state>::const_iterator it, basic_stream& dbs) -> void {
                    dbs << "{" << it->first.first << ", " << "\"" << it->first.second << "\"" << "}, ";
                    auto action = it->second.type;
                    auto target = it->second.target;
                    dbs << "{";
                    if (parser_action_t::shift == action)
                        dbs << "parser_action_t::shift";
                    else if (parser_action_t::reduce == action)
                        dbs << "parser_action_t::reduce";
                    else if (parser_action_t::accept == action)
                        dbs << "parser_action_t::accept";
                    else if (parser_action_t::error == action)
                        dbs << "parser_action_t::error";
                    dbs << ", " << target << "}";
                };

                dbs << "ACTION (GLR Multi-Map)\n";
                print_pair(_action_table, dbs, lambda_action, style);
                dbs << "\n";
                dbs << "GOTO\n";
                print_pair(_goto_table, dbs, lambda_goto, style);
                dbs << "\n";
                dbs.println("GLR table generated (conflicts allowed).");
            });
        }
#endif

        _is_table_built = true;
    }
    __finally2 {
        _context.clear();

        if (errorcode_t::success != ret) {
            _action_table.clear();
            _goto_table.clear();
        }
    }

    return ret;
}

return_t glr_parser::build(binary_parsing_table* table) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == table) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        for (const auto& item : _action_table) {
            table->buildup_action(item.first.first, item.first.second, item.second);
        }
        for (const auto& item : _goto_table) {
            table->buildup_goto(item.first.first, item.first.second, item.second);
        }
    }
    __finally2 {}
    return ret;
}

parser_type_t glr_parser::get_type() const { return parser_type_t::glr; }

return_t glr_parser::buildup_action(uint32 state, const std::string& lookahead, parser_action_state action) {
    return_t ret = errorcode_t::success;
    _action_table.emplace(std::make_pair(state, lookahead), action);
    return ret;
}

return_t glr_parser::buildup_goto(uint32 state, const std::string& nonterm, uint32 next_state) {
    return_t ret = errorcode_t::success;
    _goto_table.emplace(std::make_pair(state, nonterm), next_state);
    return ret;
}

void glr_parser::import_completed() {
    _is_table_built = true;
    _is_imported = true;
}

bool glr_parser::imported() const { return _is_imported; }

void glr_parser::addref() { _shared.addref(); }

void glr_parser::release() { _shared.delref(); }

}  // namespace io
}  // namespace hotplace
