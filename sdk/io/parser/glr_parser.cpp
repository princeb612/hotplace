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

#include <hotplace/sdk/base/basic/valist.hpp>
#include <hotplace/sdk/base/graph/gss.hpp>
#include <hotplace/sdk/base/nostd/utility.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/base/unittest/console_color.hpp>
#include <hotplace/sdk/io/parser/binary_parsing_table.hpp>
#include <hotplace/sdk/io/parser/glr_parser.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>
#include <hotplace/sdk/io/parser/parser_sdk.hpp>
#include <iomanip>
#include <iostream>
#include <list>
#include <queue>

namespace hotplace {
namespace io {

using parse_gss = t_gss<uint32, parse_treenode*>;
using parse_gss_node = parse_gss::node_type;
using parse_gss_node_ptr = parse_gss::node_ptr;

glr_parser::glr_parser() : _is_table_built(false) { _shared.make_share(this); }

glr_parser::glr_parser(const cfg_grammar& g) : glr_parser() { _grammar = g; }

glr_parser::glr_parser(cfg_grammar&& g) : glr_parser() { _grammar = std::move(g); }

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

#if defined DEBUG
// Generate a state stack string by backtracking from the GSS node to the root (parent)
static std::string build_gss_stack_string(parse_gss_node_ptr node) {
    if (nullptr == node) return "";

    std::vector<uint32> states;
    parse_gss_node_ptr curr = node;

    // Traverse up the first parent path to the root (when there are no parents)
    while (curr) {
        states.push_back(curr->state);
        if (!curr->parents.empty()) {
            curr = curr->parents[0];
        } else {
            break;
        }
    }

    std::string result;
    for (auto it = states.rbegin(); it != states.rend(); ++it) {
        result += std::to_string(*it) + " ";
    }
    return result;
}
#endif

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
                    trace.state_stack << "[ " << build_gss_stack_string(head) << " ]";

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
                            trace.state_stack << "[ " << build_gss_stack_string(head) << " ]";
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
