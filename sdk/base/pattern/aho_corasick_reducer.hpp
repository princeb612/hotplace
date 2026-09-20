/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   aho_corasick_reducer.hpp
 * @author Soo Han and Gemini
 * @desc   an extended Aho-Corasick automaton supporting token grouping, sub-pattern reduction,
 *         block suppression (treat_as), and repeat-rule processing (Parser/Reducer).
 *
 * Revision History
 * Date         Name                Description
 * 2026.08.23   Soo Han & Gemini    added virtual token reduction loop, repeat_as handling,
 *                                  and span coordinate mapping for nested pattern matching.
 * 2026.09.19   Soo Han & Gemini    block reduction (treat_as)
 *                                  collapsing the entire sequence from start to finish into a single atomic token
 */

#ifndef __HOTPLACE_SDK_BASE_PATTERN_AHOCORASICKREDUCER__
#define __HOTPLACE_SDK_BASE_PATTERN_AHOCORASICKREDUCER__

#include <algorithm>
#include <hotplace/sdk/base/pattern/aho_corasick.hpp>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace hotplace {

/**
 * @brief   linear token reducer
 * @comments
 *          exact match       : token_id
 *          group match       : token_group
 *          sub-pattern match : pattern_id
 *
 *          repeat match      : greedy loop
 *                              [token_namedtype] -> token_element
 *                              [token_element, token_taggedtype] -> token_element
 *
 *          block match       : [start, ..., finish] -> token_element
 *
 * @remarks
 *          The member function `_as` handles virtual tokens.
 * @example
 *          // sketch #1
 *          // for more examples ... see testcase_aho_corasick
 *          bool test = false;
 *
 *          t_aho_corasick_reducer<uint32> ac;
 *          ac.group_as(token_builtintype, {token_bool, token_int, token_null, token_real, token_visiblestring});
 *          ac.group_as(token_class, {token_application, token_private, token_universal});
 *          ac.group_as(token_taggedmode, {token_implicit, token_explicit});
 *          ac.insert_as(token_namedtype, {token_identifier, token_builtintype});
 *          ac.insert_as(token_tag, {token_lbracket, token_number, token_rbracket});
 *          ac.insert_as(token_tag, {token_lbracket, token_class, token_number, token_rbracket});
 *          ac.insert_as(token_tag, {token_lbracket, token_number, token_rbracket, token_taggedmode});
 *          ac.insert_as(token_tag, {token_lbracket, token_class, token_number, token_rbracket, token_taggedmode});
 *          ac.insert_as(token_taggedtype, {token_tag, token_builtintype});
 *          ac.insert_as(token_namedtype, {token_identifier, token_taggedtype});
 *
 *          // token_namedtype, token_taggedmode, token_namedtype
 *          ac.repeat_as(token_element, token_comma, {token_namedtype, token_taggedtype});
 *
 *          enum token_userdeined { token_sequencebody = token_userdefine, token_setbody };
 *          ac.insert_as(token_sequencebody, {token_sequence, token_lbrace, token_element, token_rbrace});  // SEQUENCE {name VisibleString, ok BOOLEAN}
 *          ac.insert_as(token_setbody, {token_set, token_lbrace, token_element, token_rbrace});
 *          ac.build();
 *
 *          auto lambda_test = [&ac](const std::vector<uint32>& input, const std::multimap<range_t, size_t>& expect) -> bool {
 *              auto res = ac.search(input);
 *              for (auto& pair : res) {
 *                  // pair(pos_occurrence, id_pattern)
 *                  const auto& range = pair.first;
 *                  const auto& pid = pair.second;
 *                  _logger->writeln("pos [%2zi..%2zi] pattern[%i]", range.begin, range.end, pid);
 *              }
 *              return (expect == res);
 *          };
 *
 *          // Type1 ::= SEQUENCE {name VisibleString, ok BOOLEAN}
 *          //
 *          // [00] line 1 type 36(lvalue) index 0 pos 0 len 5 (Type1)
 *          // [01] line 1 type 35(assign) index 1 pos 6 len 3 (::=)
 *          // [02] line 1 type 4110(sequence) index 2 pos 10 len 8 (SEQUENCE)
 *          // [03] line 1 type 8(lbrace) index 3 pos 19 len 1 ({)
 *          // [04] line 1 type 32(identifier) index 4 pos 20 len 4 (name)
 *          // [05] line 1 type 4122(visiblestring) index 5 pos 25 len 13 (VisibleString)
 *          // [06] line 1 type 21(comma) index 6 pos 38 len 1 (,)
 *          // [07] line 1 type 32(identifier) index 7 pos 40 len 2 (ok)
 *          // [08] line 1 type 4097(bool) index 8 pos 43 len 7 (BOOLEAN)
 *          // [09] line 1 type 9(rbrace) index 9 pos 50 len 1 (})
 *
 *          //                            0             1             2               3             4                 5                    6            7
 *          std::vector<uint32> input1 = {token_lvalue, token_assign, token_sequence, token_lbrace, token_identifier, token_visiblestring, token_comma, token_identifier,
 *          //                            8           9
 *                                        token_bool, token_rbrace};
 *          std::multimap<range_t, size_t> expect1 = {{range_t(2, 9), 7}, {range_t(4, 5), 0}, {range_t(7, 8), 0}};
 *          test = lambda_test(input1, expect1);
 *          _test_case.assert(test, __FUNCTION__, R"(group/sub-pattern/repeat search)");
 *
 *          // Person2 ::= SEQUENCE {name [0] IMPLICIT VisibleString}
 *          //
 *          // [00] line 1 type 36(lvalue) index 20 pos 0 len 7 (Person2)
 *          // [01] line 1 type 35(assign) index 1 pos 8 len 3 (::=)
 *          // [02] line 1 type 4110(sequence) index 2 pos 12 len 8 (SEQUENCE)
 *          // [03] line 1 type 8(lbrace) index 3 pos 21 len 1 ({)
 *          // [04] line 1 type 32(identifier) index 4 pos 22 len 4 (name)
 *          // [05] line 1 type 6(lbracket) index 11 pos 27 len 1 ([)
 *          // [06] line 1 type 2(number) index 21 pos 28 len 1 (0)
 *          // [07] line 1 type 7(rbracket) index 14 pos 29 len 1 (])
 *          // [08] line 1 type 4141(implicit) index 15 pos 31 len 8 (IMPLICIT)
 *          // [09] line 1 type 4122(visiblestring) index 5 pos 40 len 13 (VisibleString)
 *          // [10] line 1 type 9(rbrace) index 9 pos 53 len 1 (})
 *
 *          // clang-format off
 *          //                            0             1             2               3             4                 5               6             7
 *          std::vector<uint32> input2 = {token_lvalue, token_assign, token_sequence, token_lbrace, token_identifier, token_lbracket, token_number, token_rbracket,
 *          //                            8               9                    10
 *                                        token_implicit, token_visiblestring, token_rbrace};
 *          // clang-format on
 *          std::multimap<range_t, size_t> expect2 = {{range_t(2, 10), 7}, {range_t(4, 9), 6}, {range_t(5, 7), 1}, {range_t(5, 8), 3}, {range_t(5, 9), 5}};
 *          test = lambda_test(input2, expect2);
 *          _test_case.assert(test, __FUNCTION__, R"(group/sub-pattern/repeat search)");
 *
 *          // sketch #2
 *          // collapsing the entire sequence from start to finish into a single atomic token
 *
 *          struct memberof_parser_token {
 *              uint32 operator()(const parser_token* source, size_t idx) const { return (nullptr != source) ? (uint32)source[idx].type : 0; }
 *          };
 *          enum vtoken_t : native_token_t {
 *              vtoken_symbol = token_userdefine + 1,  // symbol group
 *              vtoken_header_clause,                  // DEFINITIONS ... ::= BEGIN
 *              vtoken_exports_clause,
 *              vtoken_imports_clause,
 *              vtoken_header_block_start,
 *              vtoken_header_block_end,
 *              vtoken_exports_clause_start,
 *              vtoken_exports_clause_end,
 *              vtoken_imports_clause_start,
 *              vtoken_imports_clause_end,
 *          };
 *
 *          t_aho_corasick_reducer<uint32, parser_token, memberof_parser_token> reducer;
 *
 *          reducer.group_as(vtoken_symbol, {token_identifier, token_usertype});
 *
 *          reducer.insert_as(vtoken_header_block_start, {vtoken_symbol, token_definitions});
 *          reducer.insert_as(vtoken_header_block_end, {token_assign, token_begin});
 *          reducer.insert_as(vtoken_exports_clause_start, {token_exports});
 *          reducer.insert_as(vtoken_imports_clause_start, {token_imports});
 *          reducer.insert_as(vtoken_exports_clause_end, {token_semicolon});
 *
 *          reducer.treat_as(vtoken_header_clause, {vtoken_header_block_start}, {vtoken_header_block_end});
 *          reducer.treat_as(vtoken_exports_clause, {vtoken_exports_clause_start}, {vtoken_exports_clause_end});
 *          reducer.treat_as(vtoken_imports_clause, {vtoken_imports_clause_start}, {vtoken_exports_clause_end});
 *
 *          reducer.build();
 *          reducer.set_greedy_filter(true);
 *
 */
template <typename BT = char, typename T = BT, typename memberof_t = memberof_defhandler<BT, T>>
class t_aho_corasick_reducer : public t_aho_corasick<BT, T, memberof_t> {
   public:
    typedef typename t_aho_corasick<BT, T, memberof_t>::trienode trienode;
    using t_aho_corasick<BT, T, memberof_t>::_root;
    using t_aho_corasick<BT, T, memberof_t>::_patterns;
    using t_aho_corasick<BT, T, memberof_t>::_memberof;
    using t_aho_corasick<BT, T, memberof_t>::apply_greedy_filter;
    using t_aho_corasick<BT, T, memberof_t>::greedy_filter;
    using t_aho_corasick<BT, T, memberof_t>::search;
    using t_aho_corasick<BT, T, memberof_t>::collect_results;

    struct pattern_info_t {
        size_t pid;
        size_t length;
        BT as_token;  // 0 or virtual token id
        bool is_virtual;
    };
    struct token_span_t {
        size_t orig_begin;
        size_t orig_end;
    };
    struct repeat_rule_t {
        BT virtual_token;                      // virtual token to be reduced
        BT delimiter_token;                    // delimiter token (none if 0)
        std::unordered_set<BT> target_tokens;  // target token set
    };
    struct treat_rule_t {
        BT virtual_token;
        std::vector<BT> begin_pattern;
        std::vector<BT> end_pattern;
    };

   public:
    t_aho_corasick_reducer(memberof_t memberof = memberof_t()) : t_aho_corasick<BT, T, memberof_t>(memberof) {}

    void insert(const std::vector<T>& pattern) override { doinsert_as(pattern.data(), pattern.size(), 0, false); }
    void insert(const T* pattern, size_t size) override { doinsert_as(pattern, size, 0, false); }

    /**
     * @brief   group
     */
    void group_as(BT group_id, const std::vector<BT>& members) {
        _group_ids.insert(group_id);
        for (const auto& member : members) {
            _token_to_groups[member].insert(group_id);
        }
    }
    /**
     * @brief   insert virtual token
     */
    void insert_as(BT virtual_token, const std::vector<T>& pattern) { doinsert_as(pattern.data(), pattern.size(), virtual_token, true); }
    void insert_as(BT virtual_token, const T* pattern, size_t size) { doinsert_as(pattern, size, virtual_token, true); }

    /**
     * @brief   repeat virtual token
     * @remarks mutual exclusion with treat_as
     *          1) repeat_as with delimiter (e.g., token_element, token_comma, {token_namedtype, token_taggedtype})
     *          2) repeat_as without a delimiter
     * @sa      treat_as
     */
    void repeat_as(BT virtual_token, BT delimiter_token, const std::vector<BT>& target_tokens) {
        repeat_rule_t info;
        info.virtual_token = virtual_token;
        info.delimiter_token = delimiter_token;
        for (const auto& t : target_tokens) {
            info.target_tokens.insert(t);
        }
        _repeat_rules.push_back(std::move(info));
    }
    void repeat_as(BT virtual_token, const std::vector<BT>& target_tokens) { repeat_as(virtual_token, 0, target_tokens); }
    /**
     * @brief   [simple is the best] to overcome limitations in a simple way...
     * @remarks
     *          1) mutual exclusion with repeat_as
     *
     *          2) The simplest and most definitive method to completely bypass complex state machines based on Aho-Corasick or Tries,
     *          effectively collapsing the entire sequence from start to finish into a single atomic token.
     *
     *          // sketch
     *          token_identifier DEFINITION ... ::= BEGIN
     *            CommonDefinitions DEFINITIONS AUTOMATIC TAGS ::= BEGIN
     *            ConsumerModule DEFINITIONS EXPLICIT TAGS EXTENSIBILITY IMPLIED ::= BEGIN
     *            CryptographicModule { iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) } DEFINITIONS AUTOMATIC TAGS ::= BEGIN
     *          EXPORTS ... ;
     *            EXPORTS Container{}, CustomErrorCode;
     *          IMPORTS ... ;
     *            IMPORTS AlgorithmIdentifier, ProtocolVersion FROM CommonDefinitions;
     *            IMPORTS Container{}, CustomErrorCode FROM CryptographicModule { iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) };
     */
    // treat_as rules (Single token overloads)
    void treat_as(BT virtual_token, BT begin, BT end) { treat_as(virtual_token, std::vector<BT>{begin}, std::vector<BT>{end}); }

    // treat_as rules (Vector sequence overloads)
    void treat_as(BT virtual_token, const std::vector<BT>& begin_pattern, const std::vector<BT>& end_pattern) {
        if ((begin_pattern.empty()) || (end_pattern.empty())) return;

        // 1. treat_rule_t
        treat_rule_t rule;
        rule.virtual_token = virtual_token;
        rule.begin_pattern = begin_pattern;
        rule.end_pattern = end_pattern;

        _treat_rules.push_back(rule);

        // 2. _pattern_info_map
        size_t new_pid = _pattern_info_map.size();

        pattern_info_t info;
        info.pid = new_pid;
        info.length = 0;
        info.as_token = virtual_token;
        info.is_virtual = true;

        _pattern_info_map[new_pid] = info;
    }

    // search method overriding (sub-pattern reduction integration)
    std::multimap<range_t, size_t> search(const std::vector<T>& source) const override { return search(source.data(), source.size()); }

    std::multimap<range_t, size_t> search(const T* source, size_t size) const override {
        if ((nullptr == source) || 0 == size) return {};

        std::vector<BT> stream;
        stream.reserve(size);
        for (size_t i = 0; i < size; ++i) {
            stream.push_back(_memberof(source, i));
        }

        std::vector<token_span_t> spans(size);
        for (size_t i = 0; i < size; ++i) {
            spans[i] = {i, i};
        }

        std::set<std::pair<range_t, size_t>> unique_results;

        bool reduced = true;
        while (reduced) {
            reduced = false;

            std::map<size_t, std::set<size_t>> ordered;
            std::multimap<range_t, size_t> step_res;
            dosearch_bt(stream.data(), stream.size(), ordered);
            this->get_result(ordered, step_res, stream.size());

            // 1. scale the matching result after transforming the original coordinates.
            for (const auto& pair : step_res) {
                const range_t& cur_range = pair.first;
                size_t pid = pair.second;
                unique_results.insert({{spans[cur_range.begin].orig_begin, spans[cur_range.end].orig_end}, pid});
            }

            // 2. select the longest virtual pattern (ambiguous grammar & maximal munch selection)
            int target_idx = -1;
            size_t max_len = 0;
            bool target_is_virtual = false;
            std::vector<std::pair<range_t, size_t>> vec_res(step_res.begin(), step_res.end());

            for (size_t i = 0; i < vec_res.size(); ++i) {
                size_t pid = vec_res[i].second;
                auto iter = _pattern_info_map.find(pid);
                if ((iter != _pattern_info_map.end()) && (iter->second.is_virtual)) {
                    size_t len = vec_res[i].first.end - vec_res[i].first.begin + 1;
                    if ((len > max_len) || ((len == max_len) && (false == target_is_virtual))) {
                        max_len = len;
                        target_idx = static_cast<int>(i);
                        target_is_virtual = true;
                    }
                }
            }

            // 3. perform virtual token reduction (in-place swap & erase optimization)
            if (-1 != target_idx) {
                const range_t& cur_range = vec_res[target_idx].first;
                size_t pid = vec_res[target_idx].second;
                const BT& vtoken = _pattern_info_map.at(pid).as_token;

                token_span_t reduced_span = {spans[cur_range.begin].orig_begin, spans[cur_range.end].orig_end};
                size_t reduce_len = cur_range.end - cur_range.begin;

                stream[cur_range.begin] = vtoken;
                spans[cur_range.begin] = reduced_span;

                if (0 < reduce_len) {
                    stream.erase(stream.begin() + cur_range.begin + 1, stream.begin() + cur_range.end + 1);
                    spans.erase(spans.begin() + cur_range.begin + 1, spans.begin() + cur_range.end + 1);
                }

                reduced = true;

                continue;  // since the virtual pattern has been reduced, the next pass
            }

            // 4. Evaluate treat_as rules first
            bool treat_as_applied = apply_treat_rules(stream, spans, unique_results);
            if (true == treat_as_applied) {
                reduced = true;
                continue;  // Skip repeat_as completely when treat_as was executed
            }

            // 5. Evaluate repeat_as rules (Mutual exclusion with treat_as)
            reduced = apply_repeat_rules(stream, spans);
        }

        std::multimap<range_t, size_t> final_results;
        for (const auto& item : unique_results) {
            final_results.insert({item.first, item.second});
        }
        if (apply_greedy_filter()) {
            final_results = greedy_filter(final_results);
        }
        return final_results;
    }

    size_t get_pid_by_virtual_token(BT vtoken) const {
        for (const auto& pair : _pattern_info_map) {
            if ((true == pair.second.is_virtual) && (vtoken == pair.second.as_token)) {
                return pair.second.pid;
            }
        }
        return static_cast<size_t>(-1);
    }
    size_t get_pattern_size(size_t index) const override {
        auto iter = _pattern_info_map.find(index);
        return (iter != _pattern_info_map.end()) ? iter->second.length : 0;
    }
    bool is_virtual_pattern(size_t index) const {
        auto iter = _pattern_info_map.find(index);
        return (iter != _pattern_info_map.end()) ? iter->second.is_virtual : false;
    }
    BT get_virtual_token(size_t index) const {
        auto iter = _pattern_info_map.find(index);
        return (iter != _pattern_info_map.end()) ? iter->second.as_token : 0;
    }
    void reset() override {
        t_aho_corasick<BT, T, memberof_t>::reset();
        _pattern_info_map.clear();
        _group_ids.clear();
        _token_to_groups.clear();
        _repeat_rules.clear();
        _treat_rules.clear();
    }

   protected:
    // Helper function for treat_as evaluation (< 50 lines, early return)
    bool apply_treat_rules(std::vector<BT>& stream, std::vector<token_span_t>& spans, std::set<std::pair<range_t, size_t>>& unique_results) const {
        if ((stream.empty()) || (_treat_rules.empty())) {
            return false;
        }

        for (const auto& rule : _treat_rules) {
            const auto& b_pat = rule.begin_pattern;
            const auto& e_pat = rule.end_pattern;

            if ((b_pat.empty()) || (e_pat.empty())) {
                continue;
            }

            for (size_t i = 0; i + b_pat.size() <= stream.size(); ++i) {
                if (false == std::equal(b_pat.begin(), b_pat.end(), stream.begin() + i)) {
                    continue;
                }

                size_t search_start = i + b_pat.size();
                size_t end_idx = stream.size();
                bool found = false;

                for (size_t j = search_start; j + e_pat.size() <= stream.size(); ++j) {
                    if (true == std::equal(e_pat.begin(), e_pat.end(), stream.begin() + j)) {
                        end_idx = j + e_pat.size() - 1;
                        found = true;
                        break;
                    }
                }

                if (true == found) {
                    range_t reduced_range = {spans[i].orig_begin, spans[end_idx].orig_end};

                    // add the treat_as reduction result to unique_results
                    // for the PID, find the PID with the corresponding virtual_token in _pattern_info_map or use a separate mapping
                    size_t target_pid = get_pid_by_virtual_token(rule.virtual_token);
                    if (static_cast<size_t>(-1) != target_pid) {
                        unique_results.insert({reduced_range, target_pid});
                    }

                    spans[i].orig_end = spans[end_idx].orig_end;
                    stream[i] = rule.virtual_token;

                    stream.erase(stream.begin() + i + 1, stream.begin() + end_idx + 1);
                    spans.erase(spans.begin() + i + 1, spans.begin() + end_idx + 1);
                    return true;
                }
            }
        }
        return false;
    }
    // Helper function for repeat_as evaluation (< 50 lines, early return)
    bool apply_repeat_rules(std::vector<BT>& stream, std::vector<token_span_t>& spans) const {
        if ((stream.empty()) || (_repeat_rules.empty())) {
            return false;
        }

        for (const auto& rule : _repeat_rules) {
            for (size_t i = 0; i < stream.size(); ++i) {
                if (rule.target_tokens.count(stream[i]) > 0) {
                    stream[i] = rule.virtual_token;
                    return true;
                }

                if (stream[i] == rule.virtual_token) {
                    size_t next_idx = i + 1;
                    if (0 != rule.delimiter_token) {
                        if ((next_idx < stream.size()) && (stream[next_idx] == rule.delimiter_token)) {
                            size_t elem_idx = next_idx + 1;
                            if ((elem_idx < stream.size()) && ((stream[elem_idx] == rule.virtual_token) || (rule.target_tokens.count(stream[elem_idx]) > 0))) {
                                spans[i].orig_end = spans[elem_idx].orig_end;
                                stream.erase(stream.begin() + i + 1, stream.begin() + elem_idx + 1);
                                spans.erase(spans.begin() + i + 1, spans.begin() + elem_idx + 1);
                                return true;
                            }
                        }
                    } else {
                        if ((next_idx < stream.size()) && ((stream[next_idx] == rule.virtual_token) || (rule.target_tokens.count(stream[next_idx]) > 0))) {
                            spans[i].orig_end = spans[next_idx].orig_end;
                            stream.erase(stream.begin() + i + 1, stream.begin() + next_idx + 1);
                            spans.erase(spans.begin() + i + 1, spans.begin() + next_idx + 1);
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    void doinsert_as(const T* pattern, size_t size, BT virtual_token, bool is_virtual) {
        if ((nullptr == pattern) || (0 == size)) {
            return;
        }

        trienode* current = _root;
        std::vector<BT> pat;

        for (size_t i = 0; i < size; ++i) {
            const BT& t = _memberof(pattern, i);
            pat.push_back(t);

            if (_group_ids.count(t) > 0) {
                trienode* child = current->group_children[t];
                if (nullptr == child) {
                    child = new trienode();
                    current->group_children[t] = child;
                }
                current = child;
            } else {
                trienode* child = current->children[t];
                if (nullptr == child) {
                    child = new trienode();
                    current->children[t] = child;
                }
                current = child;
            }
        }

        size_t index = _patterns.size();
        current->output.insert(index);

        pattern_info_t info;
        info.pid = index;
        info.length = size;
        info.as_token = virtual_token;
        info.is_virtual = is_virtual;

        _pattern_info_map[index] = info;
        _patterns.insert({index, std::move(pat)});
    }

    virtual void doinsert(const T* pattern, size_t size) override { doinsert_as(pattern, size, 0, false); }

    virtual void dobuild() override {
        std::queue<trienode*> q;

        for (auto& pair : _root->children) {
            pair.second->failure = _root;
            q.push(pair.second);
        }
        for (auto& pair : _root->group_children) {
            pair.second->failure = _root;
            q.push(pair.second);
        }

        auto build_links = [this](std::queue<trienode*>& q, trienode* current, bool is_group) {
            std::unordered_map<BT, trienode*>& child_map = is_group ? current->group_children : current->children;
            for (auto& pair : child_map) {
                const BT& key = pair.first;
                trienode* child = pair.second;
                trienode* failnode = current->failure;

                q.push(child);

                while (failnode != _root) {
                    auto& target = is_group ? failnode->group_children : failnode->children;
                    if (target.count(key) > 0) break;
                    failnode = failnode->failure;
                }

                auto& target = is_group ? failnode->group_children : failnode->children;
                auto iter = target.find(key);
                child->failure = (target.end() != iter) ? iter->second : _root;

                for (const auto& item : child->failure->output) {
                    child->output.insert(item);
                }
            }
        };

        while (false == q.empty()) {
            trienode* current = q.front();
            q.pop();

            build_links(q, current, false);
            build_links(q, current, true);
        }
    }

    void dosearch_bt(const BT* stream, size_t size, std::map<size_t, std::set<size_t>>& result) const {
        if ((nullptr == stream) || (0 == size)) return;

        auto find_next = [this](trienode* node, const BT& token) -> trienode* {
            auto exactmatch_iter = node->children.find(token);
            if (node->children.end() != exactmatch_iter) {
                return exactmatch_iter->second;
            }

            auto groupmatch_iter = _token_to_groups.find(token);
            if (_token_to_groups.end() != groupmatch_iter) {
                for (const BT& gid : groupmatch_iter->second) {
                    auto git = node->group_children.find(gid);
                    if (node->group_children.end() != git) {
                        return git->second;
                    }
                }
            }
            return nullptr;
        };

        trienode* current = _root;
        for (size_t i = 0; i < size; ++i) {
            const BT& t = stream[i];

            trienode* next_node = nullptr;
            while (current != _root) {
                next_node = find_next(current, t);
                if (nullptr != next_node) {
                    break;
                }
                current = current->failure;
            }

            if (nullptr == next_node) {
                next_node = find_next(_root, t);
            }

            if (nullptr != next_node) {
                current = next_node;
                collect_results(current, i, result);
            } else {
                current = static_cast<trienode*>(_root);
            }
        }
    }
    /**
     * @brief   search
     */
    virtual void dosearch(const T* source, size_t size, std::map<size_t, std::set<size_t>>& result) const {
        if (nullptr == source) return;

        auto find_next = [this](trienode* node, const BT& token) -> trienode* {
            auto exactmatch_iter = node->children.find(token);
            if (node->children.end() != exactmatch_iter) return exactmatch_iter->second;

            auto groupmatch_iter = _token_to_groups.find(token);
            if (_token_to_groups.end() != groupmatch_iter) {
                for (const BT& gid : groupmatch_iter->second) {
                    auto git = node->group_children.find(gid);
                    if (node->group_children.end() != git) return git->second;
                }
            }
            return nullptr;
        };

        trienode* current = _root;
        for (size_t i = 0; i < size; ++i) {
            const BT& t = _memberof(source, i);

            trienode* next_node = nullptr;
            while (current != _root) {
                next_node = find_next(current, t);
                if (next_node) break;
                current = current->failure;
            }

            if (nullptr == next_node) next_node = find_next(_root, t);

            if (next_node) {
                current = next_node;
                collect_results(current, i, result);
            } else {
                current = static_cast<trienode*>(_root);
            }
        }
    }

   protected:
    std::unordered_map<BT, std::unordered_set<BT>> _token_to_groups;  // group match
    std::unordered_set<BT> _group_ids;                                // group match
    std::unordered_map<size_t, pattern_info_t> _pattern_info_map;     // sub-pattern match
    std::vector<repeat_rule_t> _repeat_rules;                         // repeat match
    std::vector<treat_rule_t> _treat_rules;
};

}  // namespace hotplace

#endif
