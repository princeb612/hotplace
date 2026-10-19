/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   lalr1_parser.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026-08-29   Soo Han and Gemini  study
 *
 */

#include <hotplace/sdk/base/nostd/utility.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/parser/binary_parsing_table.hpp>
#include <hotplace/sdk/io/parser/cfg_grammar.hpp>
#include <hotplace/sdk/io/parser/lalr1_parser.hpp>
#include <iomanip>
#include <iostream>
#include <queue>

namespace hotplace {
namespace io {

lalr1_parser::lalr1_parser() { _shared.make_share(this); }

lalr1_parser::lalr1_parser(const cfg_grammar& g) : lalr1_parser() { _grammar = g; }

lalr1_parser::lalr1_parser(cfg_grammar&& g) : lalr1_parser() { _grammar = std::move(g); }

lalr1_parser::~lalr1_parser() {}

void lalr1_parser::set_grammar(const cfg_grammar& g) {
    _grammar = g;
    _is_table_built = false;
}

void lalr1_parser::set_grammar(cfg_grammar&& g) {
    _grammar = std::move(g);
    _is_table_built = false;
}

const cfg_grammar& lalr1_parser::get_cfg_grammar() const { return _grammar; }

cfg_grammar& lalr1_parser::get_cfg_grammar() { return _grammar; }

// LALR(1) dynamic table creation
return_t lalr1_parser::learn() {
    return_t ret = errorcode_t::success;

    critical_section_guard guard(_lock);
    __try2 {
        compute_first_and_follow_sets(_grammar, _context);
        build_lr0_states(_grammar, _context, _goto_table);

        if (false == generate_lalr1_tables(_grammar, _context, _goto_table, _action_table)) {
            _is_table_built = false;
            ret = errorcode_t::conflict_detected;
            __leave2;
        }

#if defined DEBUG
        if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_debug)) {
            trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                print_style_t style("{", ", ", "}", 2);  // indent 2

                auto lambda_lr0_goto = [](typename std::map<std::pair<uint32, std::string>, uint32>::const_iterator it, basic_stream& dbs) -> void {
                    dbs << "{" << it->first.first << ", \"" << it->first.second << "\"}, " << it->second;
                };
                auto lambda_action = [](typename std::map<std::pair<uint32, std::string>, parser_action_state>::const_iterator it, basic_stream& dbs) -> void {
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

#if 0
                auto lambda_first_follow = [](typename std::map<std::string, std::set<std::string>>::const_iterator it, basic_stream& dbs) -> void {
                    dbs << it->first << " -> ";
                    print<std::set<std::string>, basic_stream>(it->second, dbs);
                };

                auto lambda_lr0 = [&style](typename std::vector<std::set<LR0_item>>::const_iterator it, basic_stream& dbs) -> void {
                    auto lambda = [](typename std::set<LR0_item>::const_iterator it, basic_stream& dbs) -> void {
                        const auto& item = *it;
                        dbs << "production_id " << item.production_id << " dot_pos " << item.dot_pos;
                    };
                    print(*it, dbs, lambda, style.next(2));  // nested indent += 2
                };

                dbs << "FIRST\n";
                print_pair(_first_sets, dbs, lambda_first_follow, style);
                dbs << "\n";
                dbs << "FOLLOW\n";
                print_pair(_follow_sets, dbs, lambda_first_follow, style);
                dbs << "\n";
                dbs << "LR0 STATE\n";
                print(_lr0_states, dbs, lambda_lr0, style);
                dbs << "\n";
                dbs << "LR1 GOTO\n";
                print_pair(_lr0_goto, dbs, lambda_lr0_goto, style);
                dbs << "\n";
#endif

                dbs << "ACTION\n";
                print_pair(_action_table, dbs, lambda_action, style);
                dbs << "\n";
                dbs << "GOTO\n";
                print_pair(_goto_table, dbs, lambda_lr0_goto, style);
                dbs << "\n";
                dbs.println("LALR table generated.");
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

bool lalr1_parser::ready() const {
    critical_section_guard guard(_lock);
    return _is_table_built;
}

void lalr1_parser::clear() {
    critical_section_guard guard(_lock);
    _is_table_built = false;
    _is_imported = false;
    _action_table.clear();
    _goto_table.clear();
}

return_t lalr1_parser::build(binary_parsing_table* table) {
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

parser_type_t lalr1_parser::get_type() const { return parser_type_t::lalr1; }

return_t lalr1_parser::buildup_action(uint32 state, const std::string& lookahead, parser_action_state action) {
    return_t ret = errorcode_t::success;
    _action_table.emplace(std::make_pair(state, lookahead), action);
    return ret;
}

return_t lalr1_parser::buildup_goto(uint32 state, const std::string& nonterm, uint32 next_state) {
    return_t ret = errorcode_t::success;
    _goto_table.emplace(std::make_pair(state, nonterm), next_state);
    return ret;
}

void lalr1_parser::import_completed() {
    _is_table_built = true;
    _is_imported = true;
}

bool lalr1_parser::imported() const { return _is_imported; }

void lalr1_parser::addref() { _shared.addref(); }

void lalr1_parser::release() { _shared.delref(); }

}  // namespace io
}  // namespace hotplace
