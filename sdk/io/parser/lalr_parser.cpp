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

// LALR(1) dynamic table creation
return_t lalr_parser::build_table() {
    return_t ret = errorcode_t::success;

    __try2 {
        compute_first_and_follow_sets();
        build_lr0_states();

        if (false == generate_lalr_tables()) {
            _is_table_built = false;
            ret = errorcode_t::conflict_detected;
            __leave2;
        }

#if defined DEBUG
        if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
            trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
#if 0
                dbs << "FIRST\n";
                print_pair<std::map<std::string, std::set<std::string>>, basic_stream>(
                    _first_sets, dbs, [](typename std::map<std::string, std::set<std::string>>::const_iterator it, basic_stream& dbs) -> void {
                        dbs << it->first << " -> ";
                        print<std::set<std::string>, basic_stream>(it->second, dbs);
                    });
                dbs << "\n";
                dbs << "FOLLOW\n";
                print_pair<std::map<std::string, std::set<std::string>>, basic_stream>(
                    _follow_sets, dbs, [](typename std::map<std::string, std::set<std::string>>::const_iterator it, basic_stream& dbs) -> void {
                        dbs << it->first << " -> ";
                        print<std::set<std::string>, basic_stream>(it->second, dbs);
                    });
                dbs << "\n";
                dbs << "LR0 STATE\n";
                print<std::vector<std::set<LR0_item>>, basic_stream>(
                    _lr0_states, dbs,
                    [](typename std::vector<std::set<LR0_item>>::const_iterator it, basic_stream& dbs) -> void { 
                     print<std::set<LR0_item>, basic_stream>(*it, dbs, [](typename std::set<LR0_item>::const_iterator it, basic_stream& dbs) -> void {
                        const auto& item = *it;
                        dbs << "prod_id " << item.prod_id << " dot_pos " << item.dot_pos;
                     });
                });
                dbs << "\n";
                dbs << "LR1 GOTO\n";
                print_pair<std::map<std::pair<int, std::string>, int>, basic_stream>(
                    _lr0_goto, dbs, [](typename std::map<std::pair<int, std::string>, int>::const_iterator it, basic_stream& dbs) -> void {
                        dbs << "(" << it->first.first << ":" << it->first.second << ") -> " << it->second;
                    });
                dbs << "\n";
#endif
                dbs << "ACTION\n";
                print_pair<std::map<std::pair<int, std::string>, parser_action>, basic_stream>(
                    _action_table, dbs, [](typename std::map<std::pair<int, std::string>, parser_action>::const_iterator it, basic_stream& dbs) -> void {
                        dbs << "(" << it->first.first << ":" << it->first.second << ") -> ";
                        auto action = it->second.type;
                        auto target = it->second.target;
                        if (parser_action_t::shift == action)
                            dbs << "shift";
                        else if (parser_action_t::reduce == action)
                            dbs << "reduce";
                        else if (parser_action_t::accept == action)
                            dbs << "accept";
                        else if (parser_action_t::error == action)
                            dbs << "error";
                        dbs << " target " << target;
                    });
                dbs << "\n";
                dbs << "GOTO\n";
                print_pair<std::map<std::pair<int, std::string>, int>, basic_stream>(
                    _goto_table, dbs, [](typename std::map<std::pair<int, std::string>, int>::const_iterator it, basic_stream& dbs) -> void {
                        dbs << "(" << it->first.first << ":" << it->first.second << ") -> " << it->second;
                    });
                dbs << "\n";
                dbs.println("LALR table generated.");
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

// Perform dynamically generated table-based parsing
return_t lalr_parser::parse(const std::vector<parser_token>& tokens) const {
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
        std::stack<int> state_stack;
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

            int current_state = state_stack.top();
            parser_token current_token = tokens[token_idx];

            std::string typestring;
            switch (current_token.type) {
                case token_identifier:
                case token_number:
                case token_floatingpoint:
                case token_quot_string:
                    typestring = resource->nameof(current_token.type);
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
                        va << current_state << current_token.value << current_token.type;
                        dbs.vaprintln("no parser_action for state {1} with token {2} ({3})", va);
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
                std::stack<int> temp = state_stack;
                std::vector<int> states;
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

                trace.current_token << current_token.value << " (" << current_token.type << ")";
#endif
            }

            parser_action act = act_it->second;

            // 1. Shift
            if (act.type == parser_action_t::shift) {
#if defined DEBUG
                trace.action << "shift -> State " << act.target;
                trace_stack.push_back(trace);
#endif

                state_stack.push(act.target);
                token_idx++;
            }
            // 2. Reduce
            else if (act.type == parser_action_t::reduce) {
                const auto& rule = rules[act.target];

#if defined DEBUG
                trace.action << "reduce -> Rule " << rule.id << " (" << rule.lhs << ")";
                trace_stack.push_back(trace);
#endif

                for (size_t i = 0; i < rule.rhs.size(); ++i) {
                    if (false == state_stack.empty()) {
                        state_stack.pop();
                    }
                }

                if (state_stack.empty()) {
                    break;
                }

                int top_state = state_stack.top();
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

void lalr_parser::compute_first_and_follow_sets() {
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

std::set<LR0_item> lalr_parser::closure_lr0(std::set<LR0_item> items) const {
    const auto& rules = _grammar.get_productions();
    bool added = true;
    while (added) {
        added = false;
        std::set<LR0_item> new_items = items;
        for (const auto& item : items) {
            const auto& rule = rules[item.prod_id];
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

void lalr_parser::build_lr0_states() {
    const auto& rules = _grammar.get_productions();
    _lr0_states.clear();
    _lr0_goto.clear();
    _goto_table.clear();

    std::set<LR0_item> start_set = closure_lr0({{0, 0}});
    _lr0_states.push_back(start_set);

    std::queue<int> worklist;
    worklist.push(0);

    while (false == worklist.empty()) {
        int state_id = worklist.front();
        worklist.pop();

        std::set<std::string> symbols;
        for (const auto& item : _lr0_states[state_id]) {
            const auto& rule = rules[item.prod_id];
            if (item.dot_pos < rule.rhs.size()) {
                symbols.insert(rule.rhs[item.dot_pos]);
            }
        }

        for (const auto& sym : symbols) {
            std::set<LR0_item> goto_items;
            for (const auto& item : _lr0_states[state_id]) {
                const auto& rule = rules[item.prod_id];
                if (item.dot_pos < rule.rhs.size() && rule.rhs[item.dot_pos] == sym) {
                    goto_items.insert({item.prod_id, item.dot_pos + 1});
                }
            }
            std::set<LR0_item> next_state = closure_lr0(goto_items);

            int existing_state = -1;
            for (size_t i = 0; i < _lr0_states.size(); ++i) {
                if (_lr0_states[i] == next_state) {
                    existing_state = static_cast<int>(i);
                    break;
                }
            }

            if (existing_state == -1) {
                _lr0_states.push_back(next_state);
                existing_state = static_cast<int>(_lr0_states.size() - 1);
                worklist.push(existing_state);
            }

            _lr0_goto[{state_id, sym}] = existing_state;

            if (_grammar.is_non_terminal(sym)) {
                _goto_table[{state_id, sym}] = existing_state;
            }
        }
    }
}

bool lalr_parser::generate_lalr_tables() {
    const auto& rules = _grammar.get_productions();
    const auto& terminals = _grammar.get_terminals();
    bool has_conflict = false;
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
                    const auto& rule = rules[item.prod_id];
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
                const auto& rule = rules[item.prod_id];
                if (item.dot_pos < rule.rhs.size()) {
                    std::string sym = rule.rhs[item.dot_pos];
                    int next_st = _lr0_goto[{static_cast<int>(i), sym}];
                    if (lalr_states[next_st].insert({item.prod_id, item.dot_pos + 1, item.lookahead}).second) {
                        changed = true;
                    }
                }
            }
        }
    }

#if defined DEBUG
    // Helper lambda for debug printing actions
    auto format_action = [&](const parser_action& act) -> std::string {
        if (act.type == parser_action_t::shift) {
            return "Shift(" + std::to_string(act.target) + ")";
        } else if (act.type == parser_action_t::reduce) {
            const auto& r = rules[act.target];
            return "Reduce(" + std::to_string(act.target) + ": " + r.lhs + ")";
        } else if (act.type == parser_action_t::accept) {
            return "Accept";
        }
        return "Error";
    };
#endif

    for (size_t i = 0; i < lalr_states.size(); ++i) {
        for (const auto& item : lalr_states[i]) {
            const auto& rule = rules[item.prod_id];

            if (item.dot_pos < rule.rhs.size()) {
                std::string sym = rule.rhs[item.dot_pos];
                if (terminals.count(sym)) {
                    int next_st = _lr0_goto[{static_cast<int>(i), sym}];
                    auto key = std::make_pair(static_cast<int>(i), sym);
                    parser_action new_act = {parser_action_t::shift, next_st};

                    if (_action_table.count(key)) {
                        parser_action old_act = _action_table[key];
                        if (old_act.type != new_act.type || old_act.target != new_act.target) {
#if defined DEBUG
                            if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
                                trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                                    dbs << "[CONFLICT DETECTED] state " << i << " on symbol '" << sym << "': " << format_action(old_act) << " vs "
                                        << format_action(new_act) << "\n";
                                });
                            }
#endif

                            has_conflict = true;
                        }
                    } else {
                        _action_table[key] = new_act;
                    }
                }
            } else {
                if (item.prod_id == 0) {
                    _action_table[{static_cast<int>(i), "$"}] = {parser_action_t::accept, 0};
                } else {
                    auto key = std::make_pair(static_cast<int>(i), item.lookahead);
                    parser_action new_act = {parser_action_t::reduce, item.prod_id};

                    if (_action_table.count(key)) {
                        parser_action old_act = _action_table[key];
                        if (old_act.type != new_act.type || old_act.target != new_act.target) {
#if defined DEBUG
                            if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
                                trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                                    dbs << "[CONFLICT DETECTED] state " << i << " on lookahead '" << item.lookahead << "': " << format_action(old_act) << " vs "
                                        << format_action(new_act) << "\n";
                                    dbs << "  - attempted rule: " << rule.id << " -> " << rule.lhs << "\n";
                                });
                            }
#endif
                            has_conflict = true;
                        }
                    } else {
                        _action_table[key] = new_act;
                    }
                }
            }
        }
    }

    return !has_conflict;
}

}  // namespace io
}  // namespace hotplace
