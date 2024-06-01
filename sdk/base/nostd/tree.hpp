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

#ifndef __HOTPLACE_SDK_BASE_NOSTD_TREE__
#define __HOTPLACE_SDK_BASE_NOSTD_TREE__

#include <deque>
#include <functional>
#include <map>
#include <sdk/base/error.hpp>
#include <sdk/base/stl.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

// class huffman_coding;
/**
 * @brief   t_btree
 * @refer   Data Structures and Algorithm Analysis in C++ - 4.3 The Search Tree ADT - Binary Search Trees
 */
template <typename key_t, typename comparator_t = std::less<key_t>>
class t_btree {
    // friend class huffman_coding;

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
    t_btree(const t_btree &rhs) : _root(nullptr), _size(0) { _root = clone(rhs._root); }
    t_btree(t_btree &&rhs) : _root(nullptr), _size(0) {
        _root = rhs._root;
        _size = rhs._size;
        rhs._root = nullptr;
        rhs._size = 0;
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

    t_btree &operator=(const t_btree &rhs) {
        clear();
        _root = clone(rhs._root);
    }
    t_btree &operator=(t_btree &&rhs) {
        clear();
        _root = rhs._root;
        _size = rhs._size;
        rhs._root = nullptr;
        rhs._size = 0;
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
        __finally2 {
            // do nothing
        }
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

/**
 * @brief   t_avltree
 * @refer   Data Structures and Algorithm Analysis in C++ - 4.4 AVL Trees
 * @comments
 *          changes(added) - height, balance, rotate_xxx
 */
template <typename key_t, typename comparator_t = std::less<key_t>>
class t_avltree {
   private:
    struct avlnode {
        key_t _key;
        avlnode *_left;
        avlnode *_right;

        // AVL features
        int _height;

        avlnode(const key_t &key, avlnode *lt = nullptr, avlnode *rt = nullptr, int height = 0) : _key(key), _left(lt), _right(rt), _height(height) {}
        avlnode(key_t &&key, avlnode *lt = nullptr, avlnode *rt = nullptr, int height = 0) : _key{std::move(key)}, _left(lt), _right(rt), _height(height) {}
    };

   public:
    typedef avlnode node_t;
    typedef typename std::function<void(key_t const &t)> const_visitor;
    typedef typename std::function<void(key_t &t)> visitor;

    t_avltree() : _root(nullptr), _size(0) {}
    t_avltree(const t_avltree &rhs) : _root(nullptr), _size(0) { _root = clone(rhs._root); }
    t_avltree(t_avltree &&rhs) : _root(nullptr), _size(0) {
        _root = rhs._root;
        _size = rhs._size;
        rhs._root = nullptr;
        rhs._size = 0;
    }
    ~t_avltree() { clear(); }

    bool contains(const key_t &x) const { return contains(x, _root); }
    bool empty() const { return (nullptr == _root); }
    size_t size() const { return _size; }
    void for_each(const_visitor visit) { walk(_root, visit); }

    void clear() { clear(_root); }
    void insert(const key_t &x, visitor visit = nullptr) { insert(x, _root, visit); }
    void insert(key_t &&x, visitor visit = nullptr) { insert(x, _root, visit); }
    void remove(const key_t &x) { remove(x, _root); }

    t_avltree &operator=(const t_avltree &rhs) {
        clear();
        _root = clone(rhs._root);
    }
    t_avltree &operator=(t_avltree &&rhs) {
        clear();
        _root = rhs._root;
        _size = rhs._size;
        rhs._root = nullptr;
        rhs._size = 0;
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

        balance(t);

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

        balance(t);

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
        balance(t);
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
        __finally2 {
            // do nothing
        }
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

    //
    // AVL features
    //

    int height(node_t *t) const { return t ? t->_height : -1; }
    static const int ALLOWED_IMBALANCE = 1;

    void balance(node_t *&t) {
        if (t) {
            if (height(t->_left) - height(t->_right) > ALLOWED_IMBALANCE) {
                if (height(t->_left->_left) >= height(t->_left->_right)) {
                    rotate_left(t);
                } else {
                    rotate_left2(t);
                }
            } else if (height(t->_right) - height(t->_left) > ALLOWED_IMBALANCE) {
                if (height(t->_right->_right) >= height(t->_right->_left)) {
                    rotate_right(t);
                } else {
                    rotate_right2(t);
                }
            }
            t->_height = std::max(height(t->_left), height(t->_right)) + 1;
        }
    }
    void rotate_left(node_t *&k2) {
        node_t *k1 = k2->_left;
        k2->_left = k1->_right;
        k1->_right = k2;
        k2->_height = std::max(height(k2->_left), height(k2->_right)) + 1;
        k1->_height = std::max(height(k1->_left), k2->_height) + 1;
        k2 = k1;
    }
    void rotate_left2(node_t *&k3) {
        rotate_right(k3->_left);
        rotate_left(k3);
    }
    void rotate_right(node_t *&k2) {
        node_t *k1 = k2->_right;
        k2->_right = k1->_left;
        k1->_left = k2;
        k2->_height = std::max(height(k2->_right), height(k2->_left)) + 1;
        k1->_height = std::max(height(k1->_right), k2->_height) + 1;
        k2 = k1;
    }
    void rotate_right2(node_t *&k3) {
        rotate_left(k3->_right);
        rotate_right(k3);
    }

   public:
    // added
    node_t *first() const { return find_min(_root); }
};

}  // namespace hotplace

#endif
