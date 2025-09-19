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

#ifndef __HOTPLACE_SDK_BASE_PATTERN_UKKONEN__
#define __HOTPLACE_SDK_BASE_PATTERN_UKKONEN__

#include <hotplace/sdk/base/pattern/pattern.hpp>

namespace hotplace {

/**
 * @brief   suffix tree (Ukkonen algorithm)
 * @refer   https://www.geeksforgeeks.org/ukkonens-suffix-tree-construction-part-1/
 *          https://brenden.github.io/ukkonen-animation/
 *          https://programmerspatch.blogspot.com/2013/02/ukkonens-suffix-tree-algorithm.html
 */
template <typename BT = char, typename T = BT>
class t_ukkonen {
   public:
    struct trienode;
    typedef typename std::function<BT(const T* _source, size_t idx)> memberof_t;
    typedef typename std::function<void(const BT* t, size_t size)> dump_handler;
    typedef typename std::function<void(trienode* node, int level, const BT* t, size_t size)> debug_handler;

    struct trienode {
        std::unordered_map<BT, trienode*> children;
        trienode* suffix_link;
        int start;
        int end;
        int suffix_index;

        trienode(int start = -1, int end = -1) : start(start), end(end), suffix_index(-1), suffix_link(nullptr) {}
        ~trienode() {
            for (auto item : children) {
                delete item.second;
            }
        }

        int length() { return end - start + 1; }
    };

    t_ukkonen(memberof_t memberof = memberof_defhandler<BT, T>) : _memberof(memberof) { init(_root = new trienode); }
    t_ukkonen(const T* _source, size_t size, memberof_t memberof = memberof_defhandler<BT, T>) : _memberof(memberof) {
        init(_root = new trienode);
        add(_source, size);
    }
    virtual ~t_ukkonen() { delete _root; }

    t_ukkonen<BT, T>& add(const std::vector<T>& pattern) { return add(&pattern[0], pattern.size()); }
    t_ukkonen<BT, T>& add(const T* pattern, size_t size) {
        if (pattern) {
            reset();
            for (int i = 0; i < size; ++i) {
                const BT& t = _memberof(pattern, i);
                _source.insert(_source.end(), t);
            }
            init(_root);
            int source_size = _source.size();
            for (int i = 0; i < source_size; ++i) {
                extend(i);
            }
        }
        set_suffixindex(_root, 0);
        return *this;
    }

    std::set<int> search(const std::vector<T>& pattern) { return search(&pattern[0], pattern.size()); }
    std::set<int> search(const T* pattern, size_t size) {
        std::set<int> result;
        int pos = -1;
        if (pattern) {
            trienode* current = _root;
            int i = 0;
            for (int i = 0; i < size;) {
                const BT& t = _memberof(pattern, i);
                if (current->children.end() != current->children.find(t)) {
                    trienode* child = current->children[t];
                    int len = child->length();
                    for (int j = 0; j < len && i < size; j++, i++) {
                        pos = child->start + j;
                        if (_source[pos] != _memberof(pattern, i)) {
                            return result;  // not found
                        }
                    }
                    current = child;
                } else {
                    return result;  // not found
                }
            }

            collect_suffix_indices(current, result);
        }
        return result;
    }

    t_ukkonen<BT, T>& reset() {
        if (_root->children.size()) {
            delete _root;
            _root = new trienode;
        }
        return *this;
    }

    void dump(dump_handler handler) { dump(_root, 0, handler); }
    void debug(debug_handler handler) { debug(_root, 0, handler); }

   private:
    memberof_t _memberof;
    std::vector<BT> _source;
    trienode* _root;
    trienode* _active_node;
    int _active_edge;
    int _active_length;
    int _remaining_suffix_count;

    void init(trienode* node) {
        _active_node = node;
        _active_edge = -1;
        _active_length = 0;
        _remaining_suffix_count = 0;
    }

    void extend(int pos) {
        trienode* last_new_node = nullptr;
        _remaining_suffix_count++;
        while (_remaining_suffix_count > 0) {
            if (0 == _active_length) {
                _active_edge = pos;
            }

            auto item = _active_node->children.find(_source[_active_edge]);
            if (_active_node->children.end() == item) {
                _active_node->children[_source[_active_edge]] = new trienode(pos, _source.size() - 1);
                if (last_new_node) {
                    last_new_node->suffix_link = _active_node;
                    last_new_node = nullptr;
                }
            } else {
                trienode* next = item->second;
                int len = next->length();
                if (_active_length >= len) {
                    _active_edge += len;
                    _active_length -= len;
                    _active_node = next;
                    continue;
                }

                if (_source[next->start + _active_length] == _source[pos]) {
                    _active_length++;
                    if (last_new_node) {
                        last_new_node->suffix_link = _active_node;
                        last_new_node = nullptr;
                    }
                    break;
                }

                trienode* split = new trienode(next->start, next->start + _active_length - 1);
                _active_node->children[_source[_active_edge]] = split;
                split->children[_source[pos]] = new trienode(pos, _source.size() - 1);
                next->start += _active_length;
                split->children[_source[next->start]] = next;

                if (last_new_node) {
                    last_new_node->suffix_link = split;
                }
                last_new_node = split;
            }

            _remaining_suffix_count--;

            if ((_active_node == _root) && (_active_length > 0)) {
                _active_length--;
                _active_edge = pos - _remaining_suffix_count + 1;
            } else if (_active_node != _root) {
                auto temp = _active_node->suffix_link;
                if (temp) {
                    _active_node = temp;
                } else {
                    _active_node = _root;
                }
            }
        }
    }

    void set_suffixindex(trienode* node, int height) {
        if (node) {
            for (auto child : node->children) {
                set_suffixindex(child.second, height + child.second->length());
            }
            if (node->children.empty()) {
                node->suffix_index = _source.size() - height;
            }
        }
    }

    void collect_suffix_indices(trienode* node, std::set<int>& result) {
        if (node) {
            if (-1 == node->suffix_index) {
                for (auto child : node->children) {
                    collect_suffix_indices(child.second, result);
                }
            } else {
                result.insert(node->suffix_index);
            }
        }
    }

    void dump(trienode* node, int level, dump_handler handler) {
        for (auto& child : node->children) {
            trienode* item = child.second;
            handler(&_source[item->start], item->length());
            dump(child.second, level + 1, handler);
        }
    }
    void debug(trienode* node, int level, debug_handler handler) {
        for (auto& child : node->children) {
            trienode* item = child.second;
            handler(node, level, &_source[item->start], item->length());
            debug(child.second, level + 1, handler);
        }
    }
};

}  // namespace hotplace

#endif
