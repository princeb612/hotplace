/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   aho_corasick.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2024.07.05   Soo Han, Kim        study (codename.hotplace Revision 548)
 * 2026.05.19   Soo Han, Kim        replace std::function with functor (codename.hotplace Revision 1003)
 * 2026.06.29   Soo Han, Kim        code review - Gemini (reset fixed)
 */

#ifndef __HOTPLACE_SDK_BASE_PATTERN_AHOCORASICK__
#define __HOTPLACE_SDK_BASE_PATTERN_AHOCORASICK__

#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/nostd/range.hpp>
#include <hotplace/sdk/base/pattern/pattern.hpp>
#include <unordered_set>

namespace hotplace {

/**
 * @example
 *          t_aho_corasick_t<char, char>* ac = nullptr;
 *          if (0 == option) {
 *              ac = new t_aho_corasick<char>();
 *          } else if ((option_wildcards) == (option & (option_wildcards | option_ignorecase))) {
 *              ac = new t_aho_corasick_wildcard<char>('?', '*');
 *          } else if ((option_wildcards | option_ignorecase) == (option & (option_wildcards | option_ignorecase))) {
 *              ac = new t_aho_corasick_wildcard<char, char, memberof_tolower_handler>('?', '*');
 *          }
 */
template <typename BT = char, typename T = BT>
class t_aho_corasick_t {
   public:
    virtual ~t_aho_corasick_t() = default;

    virtual void insert(const std::vector<T>& pattern) = 0;
    virtual void insert(const T* pattern, size_t size) = 0;
    virtual void build() = 0;
    virtual std::multimap<range_t, size_t> search(const std::vector<T>& source) const = 0;
    virtual std::multimap<range_t, size_t> search(const T* source, size_t size) const = 0;
    virtual size_t get_pattern_size(size_t index) const = 0;
    virtual void order_by_pattern(const std::multimap<range_t, size_t>& input, std::multimap<size_t, range_t>& output) const = 0;
    virtual return_t get_pattern(size_t index, std::vector<BT>& pattern) const = 0;
    virtual void reset() = 0;
};

/**
 * @brief   Aho-Corasick algorithm
 * @remarks
 *          multiple-patterns
 *              KMP O(n*k + m)
 *              Aho-Corasick O(n + m + z) ; z count of matches
 * @refer   https://www.javatpoint.com/aho-corasick-algorithm-for-pattern-searching-in-cpp
 *          unserstanding failure link and output
 *          https://daniel.lawrence.lu/blog/y2014m03d25/
 * @sample
 *          // search
 *          {
 *              t_aho_corasick ac;
 *              ac.insert("abc", 3);
 *              ac.insert("ab", 2);
 *              ac.insert("bc", 2);
 *              ac.insert("a", 1);
 *              ac.build();
 *              const char* text = "abcaabc";
 *              std::multimap<range_t, size_t> result;
 *              result = ac.search(text, strlen(text));
 *              for (auto [range, pid] : result) {
 *                  _logger->writeln("pos [%zi..%zi] pattern[%i]", range.begin, range.end, pid);
 *              }
 *          }
 *          // using pointer
 *          {
 *              struct token { int type; };
 *              // lambda conversion - const T* to T* const*
 *              auto memberof = [](token* const* source, size_t idx) -> int {
 *                  const token* p = source[idx];
 *                  return p->type;
 *              };
 *              t_aho_corasick<int, token*> ac(memberof);
 *          }
 *
 *          // sample.2 ignore case
 *          {
 *              t_aho_corasick<char, char, memberof_tolower_handler> ac();
 *              ac.insert("hello", 5);
 *              ac.insert("world", 5);
 *              const char* source = "Hello World ";
 *              auto result = ac.search(source, strlen(source));
 *          }
 */
template <typename BT = char, typename T = BT, typename memberof_t = memberof_defhandler<BT, T>>
class t_aho_corasick : public t_aho_corasick_t<BT, T> {
   public:
    /**
     * @brief   trie node structure
     */
    struct trienode {
        std::unordered_map<BT, trienode*> children;        // exact match
        std::unordered_map<BT, trienode*> group_children;  // group match - see t_aho_corasick_reducer
        trienode* failure;
        std::set<size_t> output;
        uint8 flag;  // single/any see t_aho_corasick_wildcard
        size_t last_visited;

        trienode() : failure(nullptr), flag(0), last_visited(0) {}
        ~trienode() { clear(); }
        void clear() {
            for (auto& item : children) {
                auto child = item.second;
                delete child;
            }
            for (auto& item : group_children) {
                auto child = item.second;
                delete child;
            }
            children.clear();
            group_children.clear();
        }
    };

   public:
    t_aho_corasick(memberof_t memberof = memberof_t()) : t_aho_corasick_t<BT, T>(), _root(new trienode), _memberof(memberof), _greedy_filter(false) {}
    virtual ~t_aho_corasick() { dodestroy(); }

    void set_greedy_filter(bool how) { _greedy_filter = how; }
    bool apply_greedy_filter() const { return _greedy_filter; }

    /**
     * @brief   insert a pattern into the trie
     */
    void insert(const std::vector<T>& pattern) override { doinsert(pattern.data(), pattern.size()); }
    void insert(const T* pattern, size_t size) override { doinsert(pattern, size); }
    /**
     * @brief   build the Aho-Corasick finite state machine
     */
    void build() override { dobuild(); }

    /**
     * @brief   search for patterns
     * @return  std::multimap<range_t, size_t>
     */
    std::multimap<range_t, size_t> search(const std::vector<T>& source) const override { return search(source.data(), source.size()); }
    std::multimap<range_t, size_t> search(const T* source, size_t size) const override {
        std::map<size_t, std::set<size_t>> ordered;
        std::multimap<range_t, size_t> result;
        dosearch(source, size, ordered);
        get_result(ordered, result, size);
        return result;
    }
    virtual size_t get_pattern_size(size_t index) const {
        size_t size = 0;
        auto iter = _patterns.find(index);
        if (_patterns.end() != iter) {
            size = iter->second.size();
        }
        return size;
    }
    /**
     * @brief   order by pattern id
     * @sample
     *          std::multimap<size_t, range_t> rearranged;
     *          ac.insert(pattern1, size_pattern1);
     *          ac.build();
     *          auto result = ac.search(source, size);
     *          ac.order_by_pattern(result, rearranged);
     *          auto iter = rearranged.lower_bound(pattern_id);
     *          if (rearranged.end() != iter) {
     *              // do something
     *          }
     */
    void order_by_pattern(const std::multimap<range_t, size_t>& input, std::multimap<size_t, range_t>& output) const override {
        output.clear();
        for (auto& pair : input) {
            output.insert({pair.second, pair.first});
        }
    }

    void reset() override {
        if (_root) {
            delete _root;
            _root = new trienode;
        }
        _patterns.clear();
    }

    return_t get_pattern(size_t index, std::vector<BT>& pattern) const override {
        return_t ret = errorcode_t::success;
        auto iter = _patterns.find(index);
        if (_patterns.end() != iter) {
            pattern = iter->second;
        } else {
            ret = errorcode_t::not_found;
            pattern.clear();
        }
        return ret;
    }

    // Gemini: Standard greedy match filtering logic.
    // Filters out overlapping lower-priority matches and resolves token ambiguity
    // before feeding the reduced token stream into the LALR parser.
    static std::multimap<range_t, size_t> greedy_filter(const std::multimap<range_t, size_t>& input) {
        std::multimap<range_t, size_t> result;

        std::vector<std::pair<range_t, size_t>> v = greedy_filter_v(input);
        for (const auto& item : v) {
            result.insert(item);
        }

        return result;
    }

    // Gemini: Greedy filtering for token reduction based on Aho-Corasick matches.
    // Applies a greedy strategy to select the longest non-overlapping match
    // or prioritize predefined virtual tokens to avoid unnecessary parser backtracking.
    static std::vector<std::pair<range_t, size_t>> greedy_filter_v(const std::multimap<range_t, size_t>& input) {
        std::vector<std::pair<range_t, size_t>> result;

        if (false == input.empty()) {
            // 1. convert to list and sort by:
            //    primary: range.begin (ascending)
            //    secondary: range.width() (descending - longest first)
            std::vector<std::pair<range_t, size_t>> items(input.begin(), input.end());

            std::sort(items.begin(), items.end(), [](const std::pair<range_t, size_t>& a, const std::pair<range_t, size_t>& b) -> bool {
                if (a.first.begin != b.first.begin) {
                    return a.first.begin < b.first.begin;
                }
                return a.first.width() > b.first.width();  // longest match priority
            });

            // 2. greedy filtering: skip matches covered by previously selected longest range
            size_t last_end = 0;
            bool isfirst = true;

            for (const auto& item : items) {
                const range_t& range = item.first;

                if ((true == isfirst) || (range.begin > last_end)) {
                    result.push_back(item);
                    last_end = range.end;
                    isfirst = false;
                }
            }
        }
        return result;
    }

   protected:
    virtual void doinsert(const T* pattern, size_t size) {
        if (nullptr == pattern || 0 == size) return;

        trienode* current = _root;
        std::vector<BT> pat;

        for (size_t i = 0; i < size; ++i) {
            const BT& t = _memberof(pattern, i);
            pat.push_back(t);
            trienode* child = current->children[t];
            if (nullptr == child) {
                child = new trienode;
                current->children[t] = child;
            }
            current = child;
        }

        size_t index = _patterns.size();
        current->output.insert(index);
        _patterns.insert({index, std::move(pat)});
    }
    virtual void dobuild() {
        std::queue<trienode*> q;

        // set failure links
        for (auto& pair : _root->children) {
            auto child = pair.second;
            child->failure = _root;
            q.push(child);
        }

        // Breadth-first traversal
        while (false == q.empty()) {
            trienode* current = q.front();
            q.pop();

            for (auto& pair : current->children) {
                const BT& key = pair.first;
                trienode* child = pair.second;
                trienode* failnode = current->failure;

                q.push(child);

                while ((failnode != _root) && (failnode->children.end() == failnode->children.find(key))) {
                    failnode = failnode->failure;
                }
                auto iter = failnode->children.find(key);
                if (failnode->children.end() == iter) {
                    child->failure = _root;
                } else {
                    child->failure = iter->second;
                }

                // merge output lists (pattern ids)
                for (const auto& item : child->failure->output) {
                    child->output.insert(item);  // cf. std::set merge c++17
                }
            }
        }
    }
    /**
     * @brief   search
     */
    virtual void dosearch(const T* source, size_t size, std::map<size_t, std::set<size_t>>& result) const {
        if (nullptr == source) return;

        trienode* current = _root;
        for (size_t i = 0; i < size; ++i) {
            const BT& t = _memberof(source, i);
            while ((current != _root) && (current->children.end() == current->children.find(t))) {
                current = current->failure;
            }

            auto iter = current->children.find(t);
            if (current->children.end() != iter) {
                current = iter->second;
                collect_results(current, i, result);
            }
        }
    }
    /*
     * @brief   collect results
     */
    virtual void collect_results(trienode* node, size_t pos, std::map<size_t, std::set<size_t>>& result) const {
        if (node) {
            for (const auto& v : node->output) {
                // v is an index of a pattern
                // pos is an end position of a pattern
                result[v].insert(pos);
            }
        }
    }
    virtual void get_result(const std::map<size_t, std::set<size_t>>& ordered, std::multimap<range_t, size_t>& result, size_t size) const {
        for (const auto& pair : ordered) {
            const auto& pid = pair.first;
            const auto& positions = pair.second;
            for (const auto& pos : positions) {
                range_t range;
                range.begin = pos - get_pattern_size(pid) + 1;
                range.end = pos;
                result.insert({range, pid});
            }
        }
        if (apply_greedy_filter()) {
            result = greedy_filter(result);
        }
    }

    virtual void dodestroy() { delete _root; }

   protected:
    trienode* _root;
    std::unordered_map<size_t, std::vector<BT>> _patterns;
    memberof_t _memberof;
    bool _greedy_filter;
};

// @refer   Gemini
template <typename KEY, typename VALUE>
bool equal(const std::multimap<KEY, VALUE>& m1, const std::multimap<KEY, VALUE>& m2) {
    bool ret = false;
    if (m1.size() == m2.size()) {
        using pairtype = std::pair<const KEY, VALUE>;

        std::unordered_multiset<pairtype, universal_pairhash> s1(m1.begin(), m1.end());
        std::unordered_multiset<pairtype, universal_pairhash> s2(m2.begin(), m2.end());

        ret = (s1 == s2);
    }
    return ret;
}

/**
 * @brief   find unmatched ranges
 * @param   const std::multimap<range_t, size_t>& results [in] sorted results
 * @param   std::vector<range_t>& unmatched [out]
 * @examples
 *          auto results = ac.search(...);
 *          // find gaps, unmatched (unlike invert, find empty spaces)
 *          find_unmatched_ranges(results, unmatched);
 */
return_t find_unmatched_ranges(const std::multimap<range_t, size_t>& results, std::vector<range_t>& unmatched);

enum class matched_t { unmatched, matched };
enum class trigger_t {
    level,  // level triggered – continuous transmission of a 'state'
    edge,   // edge-triggered – signals the 'moment of change'
};

/**
 * @examples
 *          // sketch
 *          travel_ranges(trigger_t::level, results, [](matched_t type, hotplace::range_t r, size_t pid) -> bool {
 *              if (matched_t::unmatched == type) {
 *                  // handling of all unmatched areas
 *              }
 *              return true;
 *          });
 *          travel_ranges(trigger_t::edge, results, [](matched_t type, hotplace::range_t r, size_t pid) -> bool {
 *              // detecting the edge where change occurs
 *              return true;
 *          });
 */
template <typename F>
return_t travel_ranges(trigger_t trigger, const std::multimap<hotplace::range_t, size_t>& results, F&& func) {
    return_t ret = errorcode_t::success;

    if (results.empty()) return errorcode_t::empty;

    size_t current_cursor = results.begin()->first.begin;

    if (trigger_t::level == trigger) {
        // level triggered: emit every individual range sequentially
        for (const auto& pair : results) {
            const auto& r = pair.first;
            size_t pid = pair.second;

            // unmatched gap
            if (current_cursor < r.begin) {
                hotplace::range_t gap;
                gap.begin = current_cursor;
                gap.end = r.begin - 1;

                if (gap.begin <= gap.end) {
                    bool keep_going = func(matched_t::unmatched, gap, 0);
                    if (false == keep_going) return errorcode_t::no_more;
                }
            }

            // matched interval
            if (r.begin >= current_cursor) {
                bool keep_going = func(matched_t::matched, r, pid);
                if (false == keep_going) return errorcode_t::no_more;

                current_cursor = r.end + 1;
            }
        }
    } else {
        // edge triggered: coalesce consecutive same-type states  and emit only on state transitions
        bool has_pending = false;
        matched_t pending_type = matched_t::unmatched;
        hotplace::range_t pending_range;
        size_t pending_pid = 0;

        for (const auto& pair : results) {
            const auto& r = pair.first;
            size_t pid = pair.second;

            // 1. check unmatched gap
            if (current_cursor < r.begin) {
                hotplace::range_t gap;
                gap.begin = current_cursor;
                gap.end = r.begin - 1;

                if (gap.begin <= gap.end) {
                    // edge transition check (match -> unmatched)
                    if (has_pending) {
                        if (matched_t::unmatched == pending_type) {
                            pending_range.end = gap.end;
                        } else {
                            bool keep_going = func(pending_type, pending_range, pending_pid);
                            if (false == keep_going) {
                                has_pending = false;
                                break;
                            }
                            pending_type = matched_t::unmatched;
                            pending_range = gap;
                            pending_pid = 0;
                        }
                    } else {
                        has_pending = true;
                        pending_type = matched_t::unmatched;
                        pending_range = gap;
                        pending_pid = 0;
                    }
                }
            }

            // 2. check matched interval
            if (r.begin >= current_cursor) {
                if (has_pending) {
                    if (matched_t::matched == pending_type) {
                        // merge consecutive matches into a single continuous range
                        pending_range.end = std::max(pending_range.end, r.end);
                    } else {
                        // state changed (unmatched -> match): emit pending unmatched range
                        bool keep_going = func(pending_type, pending_range, pending_pid);
                        if (false == keep_going) {
                            has_pending = false;
                            break;
                        }
                        pending_type = matched_t::matched;
                        pending_range = r;
                        pending_pid = pid;
                    }
                } else {
                    has_pending = true;
                    pending_type = matched_t::matched;
                    pending_range = r;
                    pending_pid = pid;
                }

                current_cursor = r.end + 1;
            }
        }

        // flush final pending range
        if (has_pending) {
            func(pending_type, pending_range, pending_pid);
        }
    }

    return ret;
}

/**
 * @param trigger_t trigger [in] trigger_t::level
 * @param const std::multimap<hotplace::range_t, size_t>& results [in] sorted results
 * @param std::function<bool(matched_t, hotplace::range_t, size_t)> func [in]
 */
return_t travel_ranges(trigger_t trigger, const std::multimap<hotplace::range_t, size_t>& results, std::function<bool(matched_t, hotplace::range_t, size_t)> func);

}  // namespace hotplace

#endif
