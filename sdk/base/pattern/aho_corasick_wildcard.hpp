/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_PATTERN_AHO_CORASICK_WILDCARD__
#define __HOTPLACE_SDK_BASE_PATTERN_AHO_CORASICK_WILDCARD__

#include <sdk/base/pattern/aho_corasick.hpp>

namespace hotplace {

/**
 * @brief   Aho Corasick + wildcard
 * @remarks
 *
 *          review or reflection ... Soo Han, Kim (princeb612.kr@gmail.com)
 *
 *          // sketch.1 ... aho corasick + wildcard
 *
 *          1. wildcard single(?)
 *             it's so good to understand the Aho-Corasick algorithm
 *             dosearch reimplemented using queue (first design was based on simple-loop as referenced by t_aho_corasick)
 *          2. about the starting position
 *             in t_aho_corasick, it is not really matter where the starting position is located.
 *             starting position is (ending position) - (length of pattern) + 1
 *             but, starting position is very important to handle wildcard any*
 *          3. wildcard any(*) - the problem about the starting position
 *             see sketch.2 for more details (_hidden is the key to the problem)
 *             after failing several times, search results includes range_t (see search/dosearch method)
 *             also added order_by_pattern member function (have shape-shifting overhead but is easy to search by pattern id)
 *             supplement some case about the endswith_wildcard_any and startswith_wildcard_any
 *          4. comments
 *             lambda enqueue - working with large data sets, may be able to reduce overhead by deleting data that is no longer accessed...
 *
 *          pattern
 *                  his her hers ?is h?r h*s
 *                  (0 his, 1 her, 2 hers, 3 ?is, 4 h?r, 5 ??s, 6 a?, 7 h*s)
 *          input
 *                  ahishers
 *          results
 *              results.single(?)
 *                  [01234567]
 *                   ahishers
 *                   a?              (0..1)(6)
 *                    his            (1..3)(0)
 *                    ?is            (1..3)(3)
 *                    ??s            (1..3)(5)
 *                       her         (4..6)(1)
 *                       h?r         (4..6)(4)
 *                       hers        (4..7)(2)
 *                        ??s        (5..7)(5)
 *              results.any(*)
 *                    h-s            (1..3)(7)
 *                       h--s        (4..7)(7)
 *
 *          // sketch.2 - starting position of wildcard * pattern
 *
 *          0. premise
 *             "ahishers" as an input
 *             "h*h*e" as _patterns[0]
 *             "h" as _hidden[0] (pattern up to the first wildcard *)
 *
 *           1. computation
 *
 *             a) _pattern[0] ends at 5
 *             b) _hidden[0] at [1, 4]
 *             c) container [1, 4]
 *                (1..5)[0] or (4..5)[0] ; represented as (start..end)[patternid]
 *
 *           ; figure
 *                index    01234567
 *                input    ahishers
 *                pattern   h--he    see a) and c)
 *                hidden    h  h     see b)
 *
 *           2. result
 *           ; should be (1..5)[0] not (4..5)[0]
 *             d) the stating position is earlier than the index 4 ('h')
 *                d.1) pattern[0] at least 3 items occupied implicitly ("hhe")
 *                d.2) adjust = lengthof(pattern) - lengthof(wildcard_any) = lengthof("h*h*e") - lengthof("**") = 5 - 2 = 3
 *                d.3) set adjust into hidden_tag_t::adjust
 *             e) so... find_lessthan_or_equal(container, pos - adjust + 1, wanted);
 *                e.1) occurrence of pattern at pos (Aho-Corasick return the end position of a pattern)
 *                e.2) find_lessthan_or_equal(container, 5 - 3 + 1, wanted)
 *                e.3) find_lessthan_or_equal 3 in [1, 4]
 *             f) starting position
 *                wanted - lengthof(prefix) + 1 = 1 - 1 + 1 = 1
 *                ; lengthof(_hidden[0]) = lengthof("h") = 1
 *             g) finally result is (1..5)[0]
 *
 * @sample
 *          // sample.1 wildcard *, ?
 *          {
 *              t_aho_corasick_wildcard<char> ac(memberof_defhandler<char>, '?', '*');
 *              // his her hers ?is h?r h*s
 *              ac.insert("his", 3);   // pattern 0
 *              ac.insert("her", 3);   // pattern 1
 *              ac.insert("hers", 4);  // pattern 2
 *              ac.insert("?is", 3);   // pattern 3
 *              ac.insert("h?r", 3);   // pattern 4
 *              ac.insert("??s", 3);   // pattern 5
 *              ac.insert("a?", 2);    // pattern 6
 *              ac.insert("h*s", 3);   // pattern 7
 *              ac.build();
 *              const char* source = "ahishers";
 *              std::multimap<size_t, unsigned> result;
 *              std::multimap<size_t, unsigned> expect =
 *                  {{range_t(0, 1), 6}, {range_t(1, 3), 0}, {range_t(1, 3), 3}, {range_t(1, 3), 5},
 *                   {range_t(4, 6), 1}, {range_t(4, 7), 2}, {range_t(4, 6), 4}, {range_t(5, 7), 5}}};
 *              result = ac.search(source, strlen(source));
 *              for (auto item : result) {
 *                  _logger->writeln("pos [%zi] pattern[%i]", item.first, item.second);
 *              }
 *              _test_case.assert(result == expect, __FUNCTION__, "Aho Corasick algorithm + wildcards");
 *          }
 *
 *          // sample.2 ignore case + wildcard ?, *
 *          {
 *              char memberof_tolower(const char* source, size_t idx) { return source ? std::tolower(source[idx]) : char(); }
 *              t_aho_corasick_wildcard<char> ac(memberof_tolower, '?', '*');
 *              ac.insert("we *ing", 7);
 *              ac.insert("we * old", 8);
 *              const char* source = "We don't playing because we grow old; we grow old because we stop playing.";
 *              auto result = ac.search(source, strlen(source));
 *              // (0..15)[0], (25..35)[1]), (38..48)[1], (58..72)[0] ; represented as (start..end)[patternid]
 *          }
 */
template <typename BT = char, typename T = BT>
class t_aho_corasick_wildcard : public t_aho_corasick<BT, T> {
   public:
    enum {
        flag_single = (1 << 0),
        flag_any = (1 << 1),
    };

    typedef typename t_aho_corasick<BT, T>::memberof_t memberof_t;
    typedef typename t_aho_corasick<BT, T>::trienode trienode;
    using t_aho_corasick<BT, T>::_root;
    using t_aho_corasick<BT, T>::_patterns;
    using t_aho_corasick<BT, T>::_memberof;
    using t_aho_corasick<BT, T>::collect_results;
    using t_aho_corasick<BT, T>::get_pattern_size;

   public:
    t_aho_corasick_wildcard(memberof_t memberof, const BT& wildcard_single, const BT& wildcard_any)
        : t_aho_corasick<BT, T>(memberof), _wildcard_single(wildcard_single), _wildcard_any(wildcard_any) {}

   protected:
    virtual void doinsert(const T* pattern, size_t size) {
        // sketch - same as t_aho_corasick<BT, T>::doinsert but added flag
        if (pattern && size) {
            size_t index = _patterns.size();

            trienode* current = _root;
            size_t count_any = 0;
            int modes = 0;  // begins with *, ends with * (see hidden_tag_mode_t)

            std::vector<BT> pat;
            for (size_t i = 0; i < size; ++i) {
                const BT& t = _memberof(pattern, i);
                pat.push_back(t);

                trienode* child = current->children[t];
                if (nullptr == child) {
                    child = new trienode;
                    current->children[t] = child;
                }

                if (_wildcard_single == t) {
                    current->flag |= flag_single;
                } else if (_wildcard_any == t) {
                    current->flag |= flag_any;
                    if (0 == count_any) {
                        // to find a starting position, remember pattern up to the first wildcard *
                        auto prefix_index = index + baseof_prefix;

                        current->output.insert(prefix_index);
                        hidden_tag_t tag(i);
                        _hidden.insert({prefix_index, i});
                    }
                    if (0 == i) {
                        modes |= startswith_wildcard_any;
                    } else if (size - 1 == i) {
                        modes |= endswith_wildcard_any;
                    }
                    count_any++;
                }

                current = child;
            }

            current->output.insert(index);
            _patterns.insert({index, std::move(pat)});
            if (count_any) {
                auto prefix_index = index + baseof_prefix;
                _hidden[prefix_index].adjust = size - count_any;
                _hidden[prefix_index].modes = modes;
            }
        }
    }
    virtual void dosearch(const T* source, size_t size, std::map<size_t, std::set<unsigned>>& result) {
        if (source) {
            typedef std::pair<trienode*, size_t> pair_t;
            std::set<pair_t> visit;
            std::queue<pair_t> q;

            // remember without duplicates
            auto enqueue = [&](trienode* node, size_t idx) -> void {
                if (idx < size) {
                    pair_t p = {node, idx};
                    auto iter = visit.find(p);
                    if (visit.end() == iter) {
                        q.push(p);
                        visit.insert(p);
                    }
                }
            };

            enqueue(_root, 0);

            while (false == q.empty()) {
                auto pair = q.front();  // gdb problem in MINGW (const auto& pair)
                trienode* current = pair.first;
                const auto& i = pair.second;
                visit.insert({current, i});
                q.pop();

                const BT& t = _memberof(source, i);

                while ((current != _root) && (current->children.end() == current->children.find(t)) && (false == has_wildcard(current))) {
                    current = current->failure;
                }
                auto iter = current->children.find(t);
                if (current->children.end() != iter) {
                    // case - found t
                    auto node = iter->second;
                    collect_results(node, i, result);
                    enqueue(node, i + 1);

                    // case - sibling single
                    if (current->flag & flag_single) {
                        auto single = current->children[_wildcard_single];
                        enqueue(single, i + 1);
                    }
                    // case - sibling any
                    if (current->flag & flag_any) {
                        auto any = current->children[_wildcard_any];
                        while (any->flag & flag_any) {
                            any = any->children[_wildcard_any];
                        }
                        enqueue(any, i + 1);
                    }

                    // yield - case not t
                    auto fail = current->failure;
                    if (fail) {
                        // case sibling single
                        if (fail->flag & flag_single) {
                            auto single = fail->children[_wildcard_single];
                            enqueue(single, i + 1);
                        }
                        // case sibling any
                        if (fail->flag & flag_any) {
                            auto any = fail->children[_wildcard_any];
                            while (any->flag & flag_any) {
                                any = any->children[_wildcard_any];
                            }
                            enqueue(any, i + 1);
                        }
                    }
                } else if (has_wildcard(current)) {
                    // case - not t but single
                    if (current->flag & flag_single) {
                        auto single = current->children[_wildcard_single];
                        collect_results(single, i, result);
                        enqueue(single, i + 1);
                    }
                    // case - not t but sibling any
                    if (current->flag & flag_any) {
                        enqueue(current, i + 1);

                        // case - make multple * to one *
                        auto temp = current->children[_wildcard_any];
                        while (temp->flag & flag_any) {
                            temp = temp->children[_wildcard_any];
                        }

                        // case - t after *
                        auto iter = temp->children.find(t);
                        if (temp->children.end() != iter) {
                            auto child = iter->second;
                            collect_results(child, i, result);
                            enqueue(child, i + 1);
                        }
                    }

                    // yield - case not t nor single
                    auto fail = current->failure;
                    if (fail) {
                        auto iter = fail->children.find(t);
                        if (fail->children.end() != iter) {
                            auto child = iter->second;
                            collect_results(child, i, result);
                            enqueue(child, i + 1);
                        }
                    }

                    // yield - root
                    enqueue(_root, i + 1);
                } else {
                    // yield - root
                    enqueue(_root, i + 1);
                }
            }
        }
    }

    virtual void get_result(const std::map<size_t, std::set<unsigned>>& ordered, std::multimap<range_t, unsigned>& result, size_t size) {
        for (const auto& pair : ordered) {
            const auto& v = pair.first;
            const auto& positions = pair.second;
            if (v < baseof_prefix) {
                auto prefix_v = v + baseof_prefix;
                auto iter = _hidden.find(prefix_v);
                // example
                //  "hello*world" as an input
                //  "hello*world" as _patterns[0] = length(11)
                //  "hello" as _hidden[0 + 0x10000000] = length(5)
                // so ...
                //  if (_hidden.end() == iter) ; pattern[v] not contains * ; pattern
                //  if (_hidden.end() != iter) ; pattern[v] contains *     ; prefix
                if (_hidden.end() == iter) {
                    for (auto pos : positions) {
                        range_t range;
                        range.begin = pos - get_pattern_size(v) + 1;
                        range.end = pos;

                        result.insert({range, v});
                    }
                } else {
                    auto tag = iter->second;
                    auto iter_prefix = ordered.find(v + baseof_prefix);
                    if (ordered.end() != iter_prefix) {  // always true
                        auto positions_prefix = iter_prefix->second;
                        for (auto pos : positions) {
                            range_t range;

                            range.end = pos;

                            if (startswith_wildcard_any & tag.modes) {
                                range.begin = 0;
                            } else {
                                unsigned n = pos - tag.adjust + 1;
                                unsigned p = 0;
                                find_lessthan_or_equal<unsigned>(positions_prefix, n, p);

                                range.begin = p - tag.size + 1;
                            }

                            result.insert({range, v});
                        }
                    }
                }
            } else {
                // endswith_wildcard_any
                auto iter = _hidden.find(v);
                if (_hidden.end() != iter) {
                    auto tag = iter->second;
                    if (endswith_wildcard_any & tag.modes) {
                        for (auto pos : positions) {
                            range_t range;
                            range.begin = pos - tag.adjust + 1;
                            range.end = size - 1;
                            result.insert({range, v - baseof_prefix});
                        }
                    }
                }
            }
        }
    }

   private:
    bool has_wildcard(trienode* node) { return node->flag > 0; } /* check node->flag & (flag_single | flag_any) */
    BT _wildcard_single;
    BT _wildcard_any;

    enum hidden_tag_mode_t {
        startswith_wildcard_any = (1 << 0),  // *pattern
        endswith_wildcard_any = (1 << 1),    // pattern*
    };
    struct hidden_tag_t {
        size_t size;    // size of pattern
        size_t adjust;  // see sketch.2
        int modes;      // see doinsert, hidden_tag_mode_t
        hidden_tag_t() : size(0), adjust(0), modes(0) {}
        hidden_tag_t(size_t s) : size(s), adjust(0), modes(0) {}
        hidden_tag_t(size_t s, size_t adj) : size(s), adjust(adj), modes(0) {}
        void set_mode(int flags) { modes = flags; }
    };
    std::unordered_map<size_t, hidden_tag_t> _hidden;  // pair(pid + baseof_prefix, hidden_tag_t)
    const size_t baseof_prefix = 0x10000000;
};

}  // namespace hotplace

#endif
