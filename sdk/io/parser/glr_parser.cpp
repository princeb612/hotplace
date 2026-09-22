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
        compute_first_and_follow_sets();
        build_lr0_states();

        if (false == generate_glr_tables()) {
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
        _first_sets.clear();
        _follow_sets.clear();
        _lr0_states.clear();
        _lr0_goto.clear();

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

void glr_parser::compute_first_and_follow_sets() {
    const auto& rules = _grammar.get_productions();
    const auto& terminals = _grammar.get_terminals();

    for (const auto& term : terminals) {
        _first_sets[term].insert(term);
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& rule : rules) {
            if (rule.rhs.empty()) continue;

            std::string first_rhs = rule.rhs[0];
            size_t prev_size = _first_sets[rule.lhs].size();

            for (const auto& sym : _first_sets[first_rhs]) {
                _first_sets[rule.lhs].insert(sym);
            }

            if (_first_sets[rule.lhs].size() > prev_size) {
                changed = true;
            }
        }
    }

    _follow_sets["S'"].insert("$");
    changed = true;
    while (changed) {
        changed = false;
        for (const auto& rule : rules) {
            for (size_t i = 0; i < rule.rhs.size(); ++i) {
                std::string B = rule.rhs[i];
                if (false == _grammar.is_non_terminal(B)) continue;

                size_t prev_size = _follow_sets[B].size();

                if (i + 1 < rule.rhs.size()) {
                    std::string beta = rule.rhs[i + 1];
                    for (const auto& sym : _first_sets[beta]) {
                        _follow_sets[B].insert(sym);
                    }
                } else {
                    for (const auto& sym : _follow_sets[rule.lhs]) {
                        _follow_sets[B].insert(sym);
                    }
                }

                if (_follow_sets[B].size() > prev_size) {
                    changed = true;
                }
            }
        }
    }
}

std::set<LR0_item> glr_parser::closure_lr0(std::set<LR0_item> items) const {
    const auto& rules = _grammar.get_productions();
    bool added = true;
    while (added) {
        added = false;
        std::set<LR0_item> new_items = items;
        for (const auto& item : items) {
            const auto& rule = rules[item.production_id];
            if (item.dot_pos < rule.rhs.size()) {
                std::string B = rule.rhs[item.dot_pos];
                if (_grammar.is_non_terminal(B)) {
                    for (const auto& r : rules) {
                        if (r.lhs == B) {
                            if (new_items.insert({r.id, 0}).second) {
                                added = true;
                            }
                        }
                    }
                }
            }
        }
        items = new_items;
    }
    return items;
}

void glr_parser::build_lr0_states() {
    const auto& rules = _grammar.get_productions();
    _lr0_states.clear();
    _lr0_goto.clear();
    _goto_table.clear();

    std::set<LR0_item> start_set = closure_lr0({{0, 0}});
    _lr0_states.push_back(start_set);

    std::queue<uint32> worklist;
    worklist.push(0);

    while (false == worklist.empty()) {
        uint32 state_id = worklist.front();
        worklist.pop();

        std::set<std::string> symbols;
        for (const auto& item : _lr0_states[state_id]) {
            const auto& rule = rules[item.production_id];
            if (item.dot_pos < rule.rhs.size()) {
                symbols.insert(rule.rhs[item.dot_pos]);
            }
        }

        for (const auto& sym : symbols) {
            std::set<LR0_item> goto_items;
            for (const auto& item : _lr0_states[state_id]) {
                const auto& rule = rules[item.production_id];
                if (item.dot_pos < rule.rhs.size() && rule.rhs[item.dot_pos] == sym) {
                    goto_items.insert({item.production_id, item.dot_pos + 1});
                }
            }
            std::set<LR0_item> next_state = closure_lr0(goto_items);

            uint32 existing_state = -1;
            for (size_t i = 0; i < _lr0_states.size(); ++i) {
                if (_lr0_states[i] == next_state) {
                    existing_state = static_cast<uint32>(i);
                    break;
                }
            }

            if (existing_state == (uint32)-1) {
                _lr0_states.push_back(next_state);
                existing_state = static_cast<uint32>(_lr0_states.size() - 1);
                worklist.push(existing_state);
            }

            _lr0_goto[{state_id, sym}] = existing_state;

            if (_grammar.is_non_terminal(sym)) {
                _goto_table[{state_id, sym}] = existing_state;
            }
        }
    }
}

bool glr_parser::generate_glr_tables() {
    const auto& rules = _grammar.get_productions();
    const auto& terminals = _grammar.get_terminals();

    std::vector<std::set<LR1_item>> lalr_states(_lr0_states.size());
    _action_table.clear();
    lalr_states[0].insert({0, 0, "$"});

    bool changed = true;
    while (changed) {
        changed = false;
        for (size_t i = 0; i < _lr0_states.size(); ++i) {
            std::set<LR1_item> expanded = lalr_states[i];
            bool closure_changed = true;

            while (closure_changed) {
                closure_changed = false;
                std::set<LR1_item> next_expanded = expanded;

                for (const auto& item : expanded) {
                    const auto& rule = rules[item.production_id];
                    if (item.dot_pos < rule.rhs.size()) {
                        std::string B = rule.rhs[item.dot_pos];
                        if (_grammar.is_non_terminal(B)) {
                            std::set<std::string> lookaheads;
                            if (item.dot_pos + 1 < rule.rhs.size()) {
                                std::string beta = rule.rhs[item.dot_pos + 1];
                                lookaheads = _first_sets[beta];
                            } else {
                                lookaheads.insert(item.lookahead);
                            }

                            for (const auto& r : rules) {
                                if (r.lhs == B) {
                                    for (const auto& la : lookaheads) {
                                        if (next_expanded.insert({r.id, 0, la}).second) {
                                            closure_changed = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                expanded = next_expanded;
            }
            lalr_states[i] = expanded;

            for (const auto& item : lalr_states[i]) {
                const auto& rule = rules[item.production_id];
                if (item.dot_pos < rule.rhs.size()) {
                    std::string sym = rule.rhs[item.dot_pos];
                    uint32 next_st = _lr0_goto[{static_cast<uint32>(i), sym}];
                    if (lalr_states[next_st].insert({item.production_id, item.dot_pos + 1, item.lookahead}).second) {
                        changed = true;
                    }
                }
            }
        }
    }

    // Insert actions into std::multimap without conflict rejections
    for (size_t i = 0; i < lalr_states.size(); ++i) {
        for (const auto& item : lalr_states[i]) {
            const auto& rule = rules[item.production_id];

            if (item.dot_pos < rule.rhs.size()) {
                std::string sym = rule.rhs[item.dot_pos];
                if (terminals.count(sym)) {
                    uint32 next_st = _lr0_goto[{static_cast<uint32>(i), sym}];
                    auto key = std::make_pair(static_cast<uint32>(i), sym);
                    parser_action new_act = {parser_action_t::shift, next_st};

                    _action_table.insert({key, new_act});
                }
            } else {
                if (0 == item.production_id) {
                    _action_table.insert({{static_cast<uint32>(i), "$"}, {parser_action_t::accept, 0}});
                } else {
                    auto key = std::make_pair(static_cast<uint32>(i), item.lookahead);
                    parser_action new_act = {parser_action_t::reduce, item.production_id};

                    _action_table.insert({key, new_act});
                }
            }
        }
    }

    return true;
}

}  // namespace io
}  // namespace hotplace
