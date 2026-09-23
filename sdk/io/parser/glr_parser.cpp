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
#include <hotplace/sdk/base/nostd/utility.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/base/unittest/console_color.hpp>
#include <hotplace/sdk/io/parser/glr_parser.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>
#include <hotplace/sdk/io/parser/parser_sdk.hpp>
#include <iomanip>
#include <iostream>
#include <queue>

namespace hotplace {
namespace io {

glr_parser::glr_parser(const cfg_grammar& g) : _grammar(g), _is_table_built(false) {}

glr_parser::glr_parser(cfg_grammar&& g) : _grammar(std::move(g)), _is_table_built(false) {}

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

bool glr_parser::ready() const {
    critical_section_guard guard(_lock);
    return _is_table_built;
}

// Dynamic GLR multi-action table creation
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
        if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
            trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                print_style_t style("{", ", ", "}", 2);

                auto lambda_goto = [](typename std::map<std::pair<uint32, std::string>, uint32>::const_iterator it, basic_stream& dbs) -> void {
                    dbs << "{" << it->first.first << ", \"" << it->first.second << "\"}, " << it->second;
                };

                auto lambda_action = [](typename std::multimap<std::pair<uint32, std::string>, parser_action>::const_iterator it, basic_stream& dbs) -> void {
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

return_t glr_parser::import(const std::vector<parser_production>& productions, const std::multimap<std::pair<uint32, std::string>, parser_action>& action_table,
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

return_t glr_parser::parse(const std::vector<parser_token>& tokens, parse_tree* pt) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (false == _is_table_built) {
            ret = errorcode_t::not_ready;
            __leave2;
        }

        auto resource = parser_resource::get_instance();
        std::vector<std::shared_ptr<gss_node>> active_heads;
        active_heads.push_back(std::make_shared<gss_node>(0, nullptr, nullptr));

        size_t token_idx = 0;
        size_t num_tokens = tokens.size();
        const auto& rules = _grammar.get_productions();

        bool accepted = false;

        while (false == active_heads.empty()) {
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
                    case token_userparamtype:
                    case token_paramtype:
                    case token_paramvalue:
                        typestring = resource->nameof(current_token.type);
                        break;
                    default:
                        typestring = current_token.value;
                        break;
                }
            } else {
                typestring = "$";
            }

            // PHASE 1: perform all applicable REDUCE and ACCEPT operations at the current token (typestring) position.
            std::vector<std::shared_ptr<gss_node>> reduce_queue = active_heads;
            std::set<std::pair<uint32, std::shared_ptr<gss_node>>> visited_states;

            for (const auto& h : active_heads) {
                visited_states.insert({h->state, h->parent});
            }

            size_t q_idx = 0;
            while (q_idx < reduce_queue.size()) {
                auto head = reduce_queue[q_idx++];
                auto key = std::make_pair(head->state, typestring);
                auto range = _action_table.equal_range(key);

                for (auto it = range.first; it != range.second; ++it) {
                    const auto& act = it->second;

                    if (parser_action_t::accept == act.type) {
                        if (token_idx >= num_tokens || "$" == typestring) {
                            accepted = true;
                        }
                    } else if (parser_action_t::reduce == act.type) {
                        const auto& rule = rules[act.target];
                        size_t rhs_len = rule.rhs.size();

                        auto ancestor = head;
                        for (size_t i = 0; i < rhs_len && nullptr != ancestor; ++i) {
                            ancestor = ancestor->parent;
                        }

                        if (nullptr != ancestor) {
                            auto goto_key = std::make_pair(ancestor->state, rule.lhs);
                            auto goto_it = _goto_table.find(goto_key);
                            if (goto_it != _goto_table.end()) {
                                uint32 goto_state = goto_it->second;

                                auto state_pair = std::make_pair(goto_state, ancestor);
                                // add to the queue only if the state+ancestor combination has not been visited yet.
                                if (0 == visited_states.count(state_pair)) {
                                    visited_states.insert(state_pair);

                                    if (nullptr != pt) {
                                        pt->on_reduce(rule.lhs, rhs_len);
                                    }

                                    auto new_head = std::make_shared<gss_node>(goto_state, ancestor);
                                    reduce_queue.push_back(new_head);
                                    active_heads.push_back(new_head);  // also included in the set of shift candidates
                                }
                            }
                        }
                    }
                }
            }

            if (accepted) {
                ret = errorcode_t::success;
                __leave2;
            }

            // PHASE 2: Execute SHIFT (advance token_idx only upon success)
            std::vector<std::shared_ptr<gss_node>> next_heads;
            std::set<uint32> next_states;

            for (const auto& head : active_heads) {
                auto key = std::make_pair(head->state, typestring);
                auto range = _action_table.equal_range(key);

                for (auto it = range.first; it != range.second; ++it) {
                    const auto& act = it->second;

                    if (parser_action_t::shift == act.type) {
                        // 중복 Shift 노드 병합 (GSS Merge)
                        if (0 == next_states.count(act.target)) {
                            next_states.insert(act.target);
                            if (nullptr != pt) {
                                pt->on_shift(typestring, current_token.value);
                            }
                            next_heads.push_back(std::make_shared<gss_node>(act.target, head));
                        }
                    }
                }
            }

            // syntax error if no further shifting is possible
            if (next_heads.empty()) {
#if defined DEBUG
                if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
                    trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                        valist va;
                        va << typestring << current_token.value << current_token.type;
                        dbs.vaprintln("no parser_action for state {1} with token {2} ({3})", va);
                    });
                }
#endif
                ret = errorcode_t::syntax_error;
                __leave2;
            }

            // increment the input token index and replace the stack head only after a successful shift.
            active_heads = std::move(next_heads);
            token_idx++;
        }

        if (false == accepted) {
            ret = errorcode_t::syntax_error;
        }
    }
    __finally2;

    return ret;
}

}  // namespace io
}  // namespace hotplace
