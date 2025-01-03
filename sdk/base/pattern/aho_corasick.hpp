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

#ifndef __HOTPLACE_SDK_BASE_PATTERN_AHO_CORASICK__
#define __HOTPLACE_SDK_BASE_PATTERN_AHO_CORASICK__

#include <sdk/base/basic/types.hpp>
#include <sdk/base/pattern/pattern.hpp>

namespace hotplace {

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
 *              std::multimap<range_t, unsigned> result;
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
 *              char memberof_tolower(const char* source, size_t idx) { return source ? std::tolower(source[idx]) : char(); }
 *              t_aho_corasick<char> ac(memberof_tolower);
 *              ac.insert("hello", 5);
 *              ac.insert("world", 5);
 *              const char* source = "Hello World ";
 *              auto result = ac.search(source, strlen(source));
 *          }
 */
template <typename BT = char, typename T = BT>
class t_aho_corasick {
   public:
    typedef typename std::function<BT(const T* source, size_t idx)> memberof_t;

    /**
     * @brief   trie node structure
     */
    struct trienode {
        std::unordered_map<BT, trienode*> children;
        trienode* failure;
        std::set<unsigned> output;
        uint8 flag;  // reserved

        trienode() : failure(nullptr), flag(0) {}
        ~trienode() { clear(); }
        void clear() {
            for (auto item : children) {
                auto child = item.second;
                delete child;
            }
        }
    };

   public:
    t_aho_corasick(memberof_t memberof = memberof_defhandler<BT, T>) : _root(new trienode), _memberof(memberof) {}
    virtual ~t_aho_corasick() { dodestroy(); }

    /**
     * @brief   insert a pattern into the trie
     */
    void insert(const std::vector<T>& pattern) { doinsert(&pattern[0], pattern.size()); }
    void insert(const T* pattern, size_t size) { doinsert(pattern, size); }
    /**
     * @brief   build the Aho-Corasick finite state machine
     */
    void build() { dobuild(); }

    /**
     * @brief   search for patterns
     * @return  std::multimap<range_t, unsigned>
     */
    std::multimap<range_t, unsigned> search(const std::vector<T>& source) {
        std::map<size_t, std::set<unsigned>> ordered;
        std::multimap<range_t, unsigned> result;
        auto size = source.size();
        dosearch(&source[0], size, ordered);
        get_result(ordered, result, size);
        return result;
    }
    std::multimap<range_t, unsigned> search(const T* source, size_t size) {
        std::map<size_t, std::set<unsigned>> ordered;
        std::multimap<range_t, unsigned> result;
        dosearch(source, size, ordered);
        get_result(ordered, result, size);
        return result;
    }
    virtual size_t get_pattern_size(size_t index) {
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
     *          std::multimap<unsigned, range_t> rearranged;
     *          ac.insert(pattern1, size_pattern1);
     *          ac.build();
     *          auto result = ac.search(source, size);
     *          ac.order_by_pattern(result, rearranged);
     *          auto iter = rearranged.lower_bound(pattern_id);
     *          if (rearranged.end() != iter) {
     *              // do something
     *          }
     */
    void order_by_pattern(const std::multimap<range_t, unsigned>& input, std::multimap<unsigned, range_t>& output) {
        output.clear();
        for (auto& pair : input) {
            output.insert({pair.second, pair.first});
        }
    }

    void reset() {
        delete _root;
        _root = new trienode;
        _patterns.clear();
    }

    return_t get_pattern(size_t index, std::vector<BT>& pattern) {
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

   protected:
    virtual void doinsert(const T* pattern, size_t size) {
        if (pattern) {
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
                for (auto item : child->failure->output) {
                    child->output.insert(item);  // cf. std::set merge c++17
                }
            }
        }
    }
    /**
     * @brief   search
     */
    virtual void dosearch(const T* source, size_t size, std::map<size_t, std::set<unsigned>>& result) {
        if (source) {
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
    }
    /*
     * @brief   collect results
     */
    virtual void collect_results(trienode* node, size_t pos, std::map<size_t, std::set<unsigned>>& result) {
        if (node) {
            for (const auto& v : node->output) {
                // v is an index of a pattern
                // pos is an end position of a pattern
                result[v].insert(pos);
            }
        }
    }
    virtual void get_result(const std::map<size_t, std::set<unsigned>>& ordered, std::multimap<range_t, unsigned>& result, size_t size) {
        for (const auto& pair : ordered) {
            const auto& v = pair.first;
            const auto& positions = pair.second;
            for (const auto& pos : positions) {
                range_t range;
                range.begin = pos - get_pattern_size(v) + 1;
                range.end = pos;
                result.insert({range, v});
            }
        }
    }

    virtual void dodestroy() { delete _root; }

    trienode* _root;
    std::unordered_map<size_t, std::vector<BT>> _patterns;
    memberof_t _memberof;
};

}  // namespace hotplace

#endif
