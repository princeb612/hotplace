/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   lalr_parser.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026-08-29   Soo Han and Gemini  study
 *
 */

#include <hotplace/sdk/base/basic/valist.hpp>
#include <hotplace/sdk/base/nostd/utility.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/base/unittest/console_color.hpp>
#include <hotplace/sdk/io/parser/lalr_parser.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>
#include <hotplace/sdk/io/parser/parser_sdk.hpp>
#include <iomanip>
#include <iostream>
#include <queue>

namespace hotplace {
namespace io {

lalr_parser::lalr_parser(const cfg_grammar& g) : _grammar(g) {}

lalr_parser::lalr_parser(cfg_grammar&& g) : _grammar(std::move(g)) {}

void lalr_parser::set_grammar(const cfg_grammar& g) {
    _grammar = g;
    _is_table_built = false;
}

void lalr_parser::set_grammar(cfg_grammar&& g) {
    _grammar = std::move(g);
    _is_table_built = false;
}

const cfg_grammar& lalr_parser::get_cfg_grammar() const { return _grammar; }

// LALR(1) dynamic table creation
return_t lalr_parser::learn() {
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
        if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
            trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                print_style_t style("{", ", ", "}", 2);  // indent 2

                // written to be suitable for generating pre-built LALR(1) GOTO
                auto lambda_lr0_goto = [](typename std::map<std::pair<uint32, std::string>, uint32>::const_iterator it, basic_stream& dbs) -> void {
                    dbs << "{" << it->first.first << ", \"" << it->first.second << "\"}, " << it->second;
                };
                // written to be suitable for generating pre-built LALR(1) ACTION
                auto lambda_action = [](typename std::map<std::pair<uint32, std::string>, parser_action>::const_iterator it, basic_stream& dbs) -> void {
                    static std::map<std::string, std::string> table = {
                        {"id", "SYMBOL_ID"}, {"usertype", "SYMBOL_USERTYPE"}, {"num", "SYMBOL_NUM"}, {"fp", "SYMBOL_FP"}, {"quot_string", "SYMBOL_QSTR"}};

                    dbs << "{" << it->first.first << ", ";
                    auto table_it = table.find(it->first.second);
                    if (table.end() != table_it)
                        dbs << table_it->second;
                    else
                        dbs << "\"" << it->first.second << "\"";
                    dbs << "}, ";
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

return_t lalr_parser::import(const std::vector<parser_production>& productions, const std::map<std::pair<uint32, std::string>, parser_action>& action_table,
                             const std::map<std::pair<uint32, std::string>, uint32>& goto_table) {
    return_t ret = errorcode_t::success;
    critical_section_guard guard(_lock);
    _grammar.clear();
    _grammar._productions = productions;
    _action_table = action_table;
    _goto_table = goto_table;
    _is_table_built = true;
    return ret;
}

bool lalr_parser::ready() const {
    critical_section_guard guard(_lock);
    return _is_table_built;
}

// Perform dynamically generated table-based parsing
return_t lalr_parser::parse(const std::vector<parser_token>& tokens, parse_tree* pt) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (false == _is_table_built) {
#if defined DEBUG
            if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
                trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal,
                                  [&](basic_stream& dbs) -> void { dbs.println("parsing table is not built yet."); });
            }
#endif
            ret = errorcode_t::not_ready;
            __leave2;
        }

        auto resource = parser_resource::get_instance();
        std::stack<uint32> state_stack;
        state_stack.push(0);

        size_t token_idx = 0;

        const auto& rules = _grammar.get_productions();
#if defined DEBUG
        struct trace_info {
            basic_stream state_stack;
            basic_stream current_token;
            basic_stream action;
        };
        std::list<trace_info> trace_stack;
#endif

        while (true) {
            if (token_idx >= tokens.size()) {
#if defined DEBUG
                if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
                    trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal,
                                      [&](basic_stream& dbs) -> void { dbs.println("unexpected end of tokens."); });
                }
#endif
                ret = errorcode_t::unexpected;
                break;
            }

            uint32 current_state = state_stack.top();
            parser_token current_token = tokens[token_idx];

            std::string typestring;
            switch (current_token.type) {
                case token_identifier:
                case token_number:
                case token_floatingpoint:
                case token_quot_string:
                case token_usertype:
                case token_userparamtype:
                case token_paramtype:
                case token_paramvalue:
                    typestring = resource->nameof(current_token.type); /* context-sensitive */
                    break;
                default:
                    typestring = current_token.value;
                    break;
            }
            auto key = std::make_pair(current_state, typestring);
            auto act_it = _action_table.find(key);
            if (act_it == _action_table.end()) {
#if defined DEBUG
                if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
                    trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                        valist va;
                        va << current_state << typestring << current_token.value << current_token.type;
                        dbs.vaprintln("no parser_action for state {1}:{2} with token {3} ({4})", va);
                    });
                }
#endif
                ret = errorcode_t::mismatch;
                break;
            }

#if defined DEBUG
            trace_info trace;
#endif

            // state_stack
            {
                std::stack<uint32> temp = state_stack;
                std::vector<uint32> states;
                while (false == temp.empty()) {
                    states.push_back(temp.top());
                    temp.pop();
                }

#if defined DEBUG
                trace.state_stack << "[ ";
                for (auto it = states.rbegin(); it != states.rend(); ++it) {
                    trace.state_stack << std::to_string(*it) + " ";
                }
                trace.state_stack << "]";

                trace.current_token << current_token.value;
                if (typestring != current_token.value) trace.current_token << " (" << typestring << ")";
#endif
            }

            parser_action act = act_it->second;

            // 1. Shift
            if (act.type == parser_action_t::shift) {
#if defined DEBUG
                trace.action << "shift -> State " << act.target;
                trace_stack.push_back(trace);
#endif

                if (pt) pt->on_shift(typestring, current_token.value);

                state_stack.push(act.target);
                token_idx++;
            }
            // 2. Reduce
            else if (act.type == parser_action_t::reduce) {
                const auto& rule = rules[act.target];

#if defined DEBUG
                trace.action << "reduce -> Rule " << rule.id << " (" << rule.lhs << ") RHS[" << rule.rhs.size() << "]";
                trace_stack.push_back(trace);
#endif

                if (pt) pt->on_reduce(rule.lhs, rule.rhs.size());

                for (size_t i = 0; i < rule.rhs.size(); ++i) {
                    if (false == state_stack.empty()) {
                        state_stack.pop();
                    }
                }

                if (state_stack.empty()) {
                    break;
                }

                uint32 top_state = state_stack.top();
                auto goto_key = std::make_pair(top_state, rule.lhs);
                auto goto_it = _goto_table.find(goto_key);
                if (goto_it == _goto_table.end()) {
#if defined DEBUG
                    if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
                        trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                            valist va;
                            va << top_state << rule.lhs;
                            dbs.vaprintln("GOTO miss at state {1} for non-terminal {2}", va);
                        });
                    }
#endif
                    ret = errorcode_t::no_data;
                    break;
                }

                state_stack.push(goto_it->second);
            }
            // 3. Accept
            else if (act.type == parser_action_t::accept) {
#if defined DEBUG
                trace.action << "accept";
                trace_stack.push_back(trace);
#endif

                break;
            } else {
                break;
            }
        }

#if defined DEBUG
        if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
            trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                size_t len_state = 20;   // longest state_stack
                size_t len_token = 10;   // longest current_token
                size_t len_action = 10;  // longest action
                const size_t pad = 2;

                for (auto it = trace_stack.begin(); it != trace_stack.end(); ++it) {
                    const auto& trace = *it;
                    if (trace.state_stack.size() > len_state) len_state = trace.state_stack.size();
                    if (trace.current_token.size() > len_token) len_token = trace.current_token.size();
                    if (trace.action.size() > len_action) len_action = trace.action.size();
                }

                // header
                {
                    basic_stream tbs;
                    tbs.printf("%%-%zis%%-%zis%%s", len_state + pad, len_token + pad);

                    console_color concolor;
                    t_stream_binder<basic_stream, console_color> colorstream(dbs);
                    colorstream << concolor.turnon().set_style(console_style_t::bold).set_fgcolor(console_color_t::cyan) << "LALR(1) Dynamic Parsing Execution Trace"
                                << concolor.turnoff() << "\n";
                    dbs.println(tbs.c_str(), "state stack", "token", "action");
                    dbs.fill(len_state + pad + len_token + pad + len_action, '-');
                    dbs.println("");
                }

                for (auto it = trace_stack.begin(); it != trace_stack.end(); ++it) {
                    const auto& trace = *it;
                    valist va;
                    va << trace.state_stack << trace.current_token << trace.action;
                    basic_stream tbs;
                    tbs.printf("{1:-%zis}{2:-%zis}{3}", len_state + pad, len_token + pad);
                    dbs.vaprintln(tbs.c_str(), va);
                }

                // footer
                {
                    dbs.fill(len_state + pad + len_token + pad + len_action, '-');
                    dbs.println("");
                }
            });
        }
#endif
    }
    __finally2;

    return ret;
}

}  // namespace io
}  // namespace hotplace
