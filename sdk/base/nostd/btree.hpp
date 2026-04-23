/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   btree.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_BTREE__
#define __HOTPLACE_SDK_BASE_NOSTD_BTREE__

#include <deque>
#include <functional>
#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/syntax.hpp>
#include <hotplace/sdk/base/types.hpp>
#include <map>

namespace hotplace {

/**
 * @brief   t_btree
 * @refer   Data Structures and Algorithm Analysis in C++ - 4.3 The Search Tree ADT - Binary Search Trees
 */
template <typename key_t, typename comparator_t = std::less<key_t>>
class t_btree {
   private:
    struct bnode {
        key_t _key;
        bnode *_left;
        bnode *_right;

        bnode(const key_t &key, bnode *lt = nullptr, bnode *rt = nullptr) : _key(key), _left(lt), _right(rt) {}
        bnode(key_t &&key, bnode *lt = nullptr, bnode *rt = nullptr) : _key{std::move(key)}, _left(lt), _right(rt) {}
    };

   public:
    typedef bnode node_t;
    typedef typename std::function<void(key_t const &t)> const_visitor;
    typedef typename std::function<void(key_t &t)> visitor;

    t_btree() : _root(nullptr), _size(0) {}
    t_btree(const t_btree &other) : _root(nullptr), _size(0) { _root = clone(other._root); }
    t_btree(t_btree &&other) : _root(nullptr), _size(0) {
        _root = other._root;
        _size = other._size;
        other._root = nullptr;
        other._size = 0;
    }
    ~t_btree() { clear(); }

    bool contains(const key_t &x) const { return contains(x, _root); }
    bool empty() const { return (nullptr == _root); }
    size_t size() const { return _size; }
    void for_each(const_visitor visit) { walk(_root, visit); }

    void clear() { clear(_root); }
    void insert(const key_t &x, visitor visit = nullptr) { insert(x, _root, visit); }
    void insert(key_t &&x, visitor visit = nullptr) { insert(std::move(x), _root, visit); }
    void remove(const key_t &x) { remove(x, _root); }

    t_btree &operator=(const t_btree &other) {
        clear();
        _root = clone(other._root);
    }
    t_btree &operator=(t_btree &&other) {
        clear();
        _root = other._root;
        _size = other._size;
        other._root = nullptr;
        other._size = 0;
    }

   private:
    node_t *_root;
    comparator_t _comparator;
    size_t _size;

    node_t *insert(const key_t &x, node_t *&t, visitor visit = nullptr) {
        node_t *p = nullptr;
        if (nullptr == t) {
            t = new node_t(x);
            _size++;
            p = t;
        } else if (_comparator(x, t->_key)) {
            p = insert(x, t->_left);
        } else if (_comparator(t->_key, x)) {
            p = insert(x, t->_right);
        } else {
            p = t;
        }

        if (p && visit) {
            visit(p->_key);
        }

        return p;
    }
    node_t *insert(key_t &&x, node_t *&t, visitor visit = nullptr) {
        node_t *p = nullptr;
        if (nullptr == t) {
            t = new node_t(std::move(x));
            _size++;
            p = t;
        } else if (_comparator(x, t->_key)) {
            p = insert(std::move(x), t->_left);
        } else if (_comparator(t->_key, x)) {
            p = insert(std::move(x), t->_right);
        } else {
            p = t;
        }

        if (p && visit) {
            visit(p->_key);
        }

        return p;
    }
    void remove(const key_t &x, node_t *&t) {
        if (nullptr == t) {
            // do nothing
        } else if (_comparator(x, t->_key)) {
            remove(x, t->_left);
        } else if (_comparator(t->_key, x)) {
            remove(x, t->_right);
        } else if (t->_left && t->_right) {
            t->_key = find_min(t->_right)->_key;
            remove(t->_key, t->_right);
        } else {
            node_t *oldone = t;
            t = (t->_left) ? t->_left : t->_right;
            delete oldone;
            _size--;
        }
    }
    node_t *find_min(node_t *t) const {
        if (nullptr != t) {
            while (t->_left) {
                t = t->_left;
            }
        }
        return t;
    }
    node_t *find_max(node_t *t) const {
        if (nullptr != t) {
            while (t->_right) {
                t = t->_right;
            }
        }
        return t;
    }
    bool contains(const key_t &x, node_t *t) const {
        bool ret = false;
        __try2 {
            if (nullptr == t) {
                __leave2;
            } else if (_comparator(x, t->_key)) {
                ret = contains(x, t->_left);
            } else if (_comparator(t->_key, x)) {
                ret = contains(x, t->_right);
            } else {
                ret = true;
            }
        }
        __finally2 {}
        return ret;
    }
    void clear(node_t *&t) {
        if (t) {
            clear(t->_left);
            clear(t->_right);
            delete t;
        }
        t = nullptr;
    }
    void walk(node_t *t, const_visitor visit) {
        if (t) {
            // in-order traverse
            walk(t->_left, visit);
            visit(t->_key);
            walk(t->_right, visit);
        }
    }
    node_t *clone(node_t *t) const {
        node_t *item = nullptr;
        if (t) {
            item = new node_t(t->_key, clone(t->_left), clone(t->_right));
        }
        return item;
    }

   public:
    // added
    node_t *root() const { return _root; }
    node_t *first() const { return find_min(_root); }
    node_t *clone_nocascade(node_t *p) { return p ? new node_t(p->_key) : nullptr; }
    node_t *add(const key_t &x, visitor visit = nullptr) { return insert(x, _root, visit); }
    void clean(node_t *&t) { clear(t); }
};

}  // namespace hotplace

#endif
