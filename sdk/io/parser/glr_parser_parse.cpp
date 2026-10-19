/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   glr_parser_parse.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc   Generalized LR (GLR) parser implementation with GSS support
 *
 * Revision History
 * Date         Name                Description
 * 2026.09.22   Soo Han and Gemini  study
 *
 */

#include <hotplace/sdk/base/basic/valist.hpp>
#include <hotplace/sdk/base/graph/gss.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/base/unittest/console_color.hpp>
#include <hotplace/sdk/io/parser/glr_parser.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>
#include <iomanip>
#include <iostream>
#include <list>
#include <queue>

namespace hotplace {
namespace io {

using parse_gss = t_gss<uint32, parse_treenode*>;
using parse_gss_node = parse_gss::node_type;
using parse_gss_node_ptr = parse_gss::node_ptr;

return_t glr_parser::parse(const std::vector<parser_token>& tokens, parse_tree* pt) {
    return_t ret = errorcode_t::success;
    size_t shifted = 0;
    size_t token_idx = 0;
#if defined DEBUG
    struct trace_info {
        basic_stream state_stack;
        basic_stream current_token;
        basic_stream action;
    };
    std::list<trace_info> trace_stack;
#endif

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

        // Initialize GSS stack with state 0
        parse_gss stack;
        stack.push_root(0, nullptr);

        size_t num_tokens = tokens.size();
        bool accepted = false;

        while (false == stack.get_heads().empty()) {
            parser_token current_token;
            std::string typestring;

            if (token_idx < num_tokens) {
                current_token = tokens[token_idx];
                switch (current_token.type) {
                    case token_identifier:
                    case token_number:
                    case token_floatingpoint:
                    case token_quot_string:
                    case token_usertype:
                    case token_hexstring:
                        typestring = resource->nameof(current_token.type);
                        break;
                    default:
                        typestring = current_token.value;
                        break;
                }
            } else {
                typestring = "$";
            }

            // PHASE 1: REDUCE and ACCEPT operations using GSS Pop/Retrace
            std::vector<parse_gss_node_ptr> reduce_queue = stack.get_heads();
            std::set<std::pair<uint32, parse_gss_node_ptr>> visited_reductions;

            size_t q_idx = 0;
            while (q_idx < reduce_queue.size()) {
                auto head = reduce_queue[q_idx++];
                auto key = std::make_pair(head->state, typestring);
                auto range = _action_table.equal_range(key);

#if defined DEBUG
                if (range.first == range.second) {
                    trace_info trace;
                    trace.action << "no ACTION[" << head->state << ":" << typestring << "] ";
                    trace_stack.push_back(trace);
                }
#endif
                for (auto it = range.first; it != range.second; ++it) {
                    const auto& act = it->second;

#if defined DEBUG
                    trace_info trace;
                    // State stack representation (head node state)
                    trace.state_stack << "[ " << stack.backtrack_string(head) << " ]";

                    trace.current_token << (token_idx < num_tokens ? current_token.value : "$");
                    if (token_idx < num_tokens && typestring != current_token.value) {
                        trace.current_token << " (" << typestring << ")";
                    }
                    trace.action << "ACTION[" << head->state << ":" << typestring << "] ";
#endif

                    if (parser_action_t::accept == act.type) {
                        if (token_idx >= num_tokens || "$" == typestring) {
                            accepted = true;
#if defined DEBUG
                            trace.action << "accept";
                            trace_stack.push_back(trace);
#endif
                        }
                    } else if (parser_action_t::reduce == act.type) {
                        const auto& rule = _grammar.get_production(act.target);
                        size_t rhs_len = rule.rhs.size();

#if defined DEBUG
                        trace.action << "reduce -> Rule " << rule.id << " (" << rule.lhs << ") RHS[" << rhs_len << "]";
#endif

                        // Utilize t_gss::pop (retrace_paths) to safely collect all paths
                        stack.pop(head, rhs_len, [&](const std::vector<parse_gss_node_ptr>& path) {
                            if (path.empty()) return;

                            // The end of the path represents the ancestor stack node after reduction
                            parse_gss_node_ptr ancestor = path.back();

                            auto goto_key = std::make_pair(ancestor->state, rule.lhs);
                            auto goto_it = _goto_table.find(goto_key);
                            if (goto_it != _goto_table.end()) {
                                uint32 goto_state = goto_it->second;

                                auto visit_key = std::make_pair(goto_state, ancestor);
                                if (0 == visited_reductions.count(visit_key)) {
                                    visited_reductions.insert(visit_key);

                                    if (nullptr != pt) {
                                        pt->on_reduce(act.target, rule.lhs, rhs_len);
                                    }

#if defined DEBUG
                                    trace_info trace_goto = trace;
                                    trace_goto.action << " -> GOTO[" << ancestor->state << ":" << rule.lhs << "] -> state " << goto_state;
                                    trace_stack.push_back(trace_goto);
#endif

                                    // Push new reduced stack node connected to ancestor
                                    auto new_head = stack.push(ancestor, goto_state, nullptr);
                                    reduce_queue.push_back(new_head);
                                }
                            }
                        });
                    }
                }
            }

            if (accepted) {
                ret = errorcode_t::success;
                __leave2;
            }

            // PHASE 2: Execute SHIFT (advance token_idx only upon success)
            std::vector<parse_gss_node_ptr> next_heads;
            std::set<uint32> next_states;
            bool do_shift = false;

            for (const auto& head : stack.get_heads()) {
                auto key = std::make_pair(head->state, typestring);
                auto range = _action_table.equal_range(key);

                for (auto it = range.first; it != range.second; ++it) {
                    const auto& act = it->second;

                    if (parser_action_t::shift == act.type) {
                        if (0 == next_states.count(act.target)) {
                            next_states.insert(act.target);

#if defined DEBUG
                            trace_info trace;
                            trace.state_stack << "[ " << stack.backtrack_string(head) << " ]";
                            trace.current_token << (token_idx < num_tokens ? current_token.value : "$");
                            if (token_idx < num_tokens && typestring != current_token.value) {
                                trace.current_token << " (" << typestring << ")";
                            }
                            trace.action << "ACTION[" << head->state << ":" << typestring << "] shift -> State " << act.target;
                            trace_stack.push_back(trace);
#endif

                            // Shift new node connected to current head
                            auto new_shift_head = stack.create_node(act.target, nullptr);
                            new_shift_head->add_parent(head);
                            next_heads.push_back(new_shift_head);

                            do_shift = true;
                        }
                    }
                }
            }

            if (do_shift) {
                if (nullptr != pt) {
                    pt->on_shift(typestring, current_token.value);
                }
                ++shifted;
            } else if (next_heads.empty()) {
#if defined DEBUG
                if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
                    trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                        valist va;
                        va << typestring << current_token.value << current_token.type << token_idx;
                        dbs.vaprintln("no parser_action_state for state {1} with token {2} ({3}) at [{4:03zi}]", va);
                    });
                }
#endif
                ret = errorcode_t::syntax_error;
                __leave2;
            }

            // Update active heads for next token shift step
            stack.clear_heads();
            for (const auto& nh : next_heads) {
                stack.add_head(nh);
            }

            ++token_idx;
        }

        if (false == accepted) {
            ret = errorcode_t::syntax_error;
            __leave2;
        }
    }
    __finally2 {
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

                // Header
                {
                    basic_stream tbs;
                    tbs.printf("%%-%zis%%-%zis%%s", len_state + pad, len_token + pad);

                    console_color concolor;
                    t_stream_binder<basic_stream, console_color> colorstream(dbs);
                    colorstream << concolor.turnon().set_style(console_style_t::bold).set_fgcolor(console_color_t::cyan) << "GLR Dynamic Parsing Execution Trace"
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

                // Footer
                {
                    dbs.fill(len_state + pad + len_token + pad + len_action, '-');
                    dbs.println("");
                }

                valist va;
                va << tokens.size() << token_idx << shifted;
                dbs.vaprintln("tokens {1} token index {2} shifted {3}", va);
            });
        }
#endif
    }

    return ret;
}

}  // namespace io
}  // namespace hotplace
