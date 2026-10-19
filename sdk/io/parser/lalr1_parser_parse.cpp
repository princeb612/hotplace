/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   lalr1_parser_parse.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026-08-29   Soo Han and Gemini  study
 *
 */

#include <hotplace/sdk/base/basic/valist.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/base/unittest/console_color.hpp>
#include <hotplace/sdk/io/parser/lalr1_parser.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>
#include <iomanip>
#include <iostream>
#include <queue>

namespace hotplace {
namespace io {

// Perform dynamically generated table-based parsing
return_t lalr1_parser::parse(const std::vector<parser_token>& tokens, parse_tree* pt) {
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

        if (pt) pt->set_parser(this);

        auto resource = parser_resource::get_instance();
        std::stack<uint32> state_stack;
        state_stack.push(0);

        size_t token_idx = 0;

        // const auto& rules = _grammar.get_productions();
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
                case token_hexstring:
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
                        dbs.vaprintln("no parser_action_state for state {1}:{2} with token {3} ({4})", va);
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

            parser_action_state act = act_it->second;

#if defined DEBUG
            trace.action << "ACTION[" << current_state << ":" << typestring << "] ";
#endif

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
                const auto& rule = _grammar.get_production(act.target);

#if defined DEBUG
                // act.target (rule.id)
                trace.action << "reduce -> Rule " << rule.id << " (" << rule.lhs << ") RHS[" << rule.rhs.size() << "]";
                trace_stack.push_back(trace);
#endif

                if (pt) pt->on_reduce(act.target, rule.lhs, rule.rhs.size());

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
                    ret = errorcode_t::not_found;
                    break;
                }

#if defined DEBUG
                auto& trace_action = *trace_stack.rbegin();
                trace_action.action << " -> GOTO[" << top_state << ":" << rule.lhs << "] -> state " << goto_it->second;
#endif
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
