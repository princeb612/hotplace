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

#ifndef __HOTPLACE_SDK_BASE_BASIC_TREE__
#define __HOTPLACE_SDK_BASE_BASIC_TREE__

#include <deque>
#include <functional>
#include <map>
#include <sdk/base/error.hpp>
#include <sdk/base/stl.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

template <typename key_t, typename comparator_t>
class huffman_coding;
/**
 * @brief   t_btree
 * @refer   Data Structures and Algorithm Analysis in C++ - 4.3 The Search Tree ADT - Binary Search Trees
 */
template <typename key_t, typename comparator_t = std::less<key_t>>
class t_btree {
    friend class huffman_coding<key_t, comparator_t>;

   private:
    struct bnode {
        key_t _key;
        bnode *_left;
        bnode *_right;

        bnode(const key_t &key, bnode *lt = nullptr, bnode *rt = nullptr) : _key(key), _left(lt), _right(rt) {}
        bnode(key_t &&key, bnode *lt = nullptr, bnode *rt = nullptr) : _key{std::move(key)}, _left(lt), _right(rt) {}
    };
    typedef bnode node_t;

   public:
    typedef typename std::function<void(key_t const &t)> const_visitor;
    typedef typename std::function<void(key_t &t)> visitor;

    t_btree() : _root(nullptr), _size(0) {}
    t_btree(const t_btree &rhs) : _root(nullptr), _size(0) { _root = clone(rhs._root); }
    t_btree(t_btree &&rhs) : _root(nullptr), _size(0) {
        if (rhs._root) {
            insert(rhs._root->_key);
        }
    }
    ~t_btree() { clear(); }

    bool contains(const key_t &x) const { return contains(x, _root); }
    bool empty() const { return (nullptr == _root); }
    size_t size() const { return _size; }
    // void printTree(ostream &out = cout) const;
    void for_each(const_visitor visit) { walk(_root, visit); }

    void clear() { clear(_root); }
    void insert(const key_t &x, visitor visit = nullptr) { insert(x, _root, visit); }
    void insert(key_t &&x, visitor visit = nullptr) { insert(x, _root, visit); }
    void remove(const key_t &x) { remove(x, _root); }

    t_btree &operator=(const t_btree &rhs) {
        clear();
        _root = clone(rhs._root);
    }
    t_btree &operator=(t_btree &&rhs) {
        clear();
        if (rhs._root) {
            insert(rhs._root->_key);
        }
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
    // void printTree(node_t *t, ostream &out) const;
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

    // added
    node_t *first() const { return find_min(_root); }
    node_t *clone_nocascade(node_t *p) { return p ? new node_t(p->_key) : nullptr; }
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
    typedef avlnode node_t;

   public:
    typedef typename std::function<void(key_t const &t)> const_visitor;
    typedef typename std::function<void(key_t &t)> visitor;

    t_avltree() : _root(nullptr), _size(0) {}
    t_avltree(const t_avltree &rhs) : _root(nullptr), _size(0) { _root = clone(rhs._root); }
    t_avltree(t_avltree &&rhs) : _root(nullptr), _size(0) {
        if (rhs._root) {
            insert(rhs._root->_key);
        }
    }
    ~t_avltree() { clear(); }

    bool contains(const key_t &x) const { return contains(x, _root); }
    bool empty() const { return (nullptr == _root); }
    size_t size() const { return _size; }
    // void printTree(ostream &out = cout) const;
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
        if (rhs._root) {
            insert(rhs._root->_key);
        }
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
    // void printTree(node_t *t, ostream &out) const;
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

    // added
    node_t *first() const { return find_min(_root); }
};

/*
 * @brief   huffman codes
 * @refer   Data Structures and Algorithm Analysis in C++ - 10.1.2 Huffman Codes
 *          Data Structures & Algorithms in C++ - 12.4.1 The Huffman-Coding Algorithm
 *          https://asecuritysite.com/calculators/huff
 */

struct huffmancoding_t {
    uint8 symbol;
    size_t weight;
    uint32 flags;

    huffmancoding_t() : symbol(0), weight(0), flags(0) {}
    huffmancoding_t(uint8 b) : symbol(b), weight(0), flags(0) {}
    huffmancoding_t(uint8 b, size_t f) : symbol(b), weight(f), flags(0) {}
    huffmancoding_t(const huffmancoding_t &rhs) : symbol(rhs.symbol), weight(rhs.weight), flags(rhs.flags) {}
    bool operator<(const huffmancoding_t &rhs) const { return symbol < rhs.symbol; }
};

template <typename T>
struct t_comparator_base {
    friend bool operator<(const T &lhs, const T &rhs) { return lhs < rhs; }
};

template <typename T>
struct t_type_comparator : t_comparator_base<T> {
    bool operator()(const T &lhs, const T &rhs) { return lhs.symbol < rhs.symbol; }
};

template <typename T>
struct t_huffmancoding_comparator : t_comparator_base<T> {
    bool operator()(const T &lhs, const T &rhs) const {
        bool ret = false;

        if (lhs.weight < rhs.weight) {
            ret = true;
        } else if (lhs.weight == rhs.weight) {
            if (lhs.flags < rhs.flags) {
                ret = true;
            } else {
                ret = lhs.symbol < rhs.symbol;
            }
        }

        return ret;
    }
};

template <typename key_t, typename comparator_t = t_huffmancoding_comparator<key_t>>
class huffman_coding {
   private:
    struct hcode {
        size_t depth;
        std::string code;

        hcode() : depth(0) {}
    };
    typedef t_btree<key_t> measure_tree_t;
    typedef t_btree<key_t, comparator_t> btree_t;
    typedef std::map<key_t, typename btree_t::node_t *, comparator_t> map_t;
    typedef std::pair<typename map_t::iterator, bool> map_pib_t;
    typedef std::map<uint8, std::string> table_t;

   public:
    typedef typename std::function<void(key_t &t, const key_t &lhs, const key_t &rhs)> learn_visitor;
    typedef typename std::function<void(key_t const &t)> const_visitor;
    typedef typename std::function<void(key_t &t)> visitor;
    typedef typename std::function<void(key_t const &t, bool &use, uint8 &symbol, size_t &weight, std::string const &)> infer_visitor;
    typedef typename btree_t::node_t node_t;

    huffman_coding() {}
    ~huffman_coding() {
        _measure.clear();
        _btree.clear();
        _m.clear();
        _table.clear();
    }

    void reset() { _measure.clear(); }

    huffman_coding &load(const char *s, visitor v) {
        // count
        for (const char *p = s; *p; p++) {
            _measure.insert(key_t((uint8)*p), v);
        }
        return *this;
    }

    huffman_coding &learn(learn_visitor v) {
        _btree.clear();
        _m.clear();
        _table.clear();
        _totalbits = 0;

        _measure.for_each([&](key_t const &t) -> void { _btree.insert(t); });

        while (_btree.size() > 1) {
            key_t k;
            key_t k_left;
            key_t k_right;

            typename btree_t::node_t *l = _btree.clone_nocascade(_btree.first());
            k_left = l->_key;
            _btree.remove(l->_key);

            typename btree_t::node_t *r = _btree.clone_nocascade(_btree.first());
            k_right = r->_key;
            _btree.remove(r->_key);

            v(k, k_left, k_right);

            typename btree_t::node_t *newone = _btree.insert(k, _btree._root);  // merged

            map_pib_t pib = _m.insert(std::make_pair(k, _btree.clone_nocascade(newone)));
            pib.first->second->_left = l;
            pib.first->second->_right = r;
        }
        return *this;
    }

    node_t *build(node_t **root = nullptr) {
        typename btree_t::node_t *p = nullptr;
        if (_m.size()) {
            p = _m.rbegin()->second;
            _m.erase(p->_key);

            while (_m.size()) {
                build(p);
            }

            if (root) {
                *root = p;
            }
        }
        return p;
    }
    void infer(node_t *root, infer_visitor v) {
        if (root && v) {
            hcode hc;
            infer(hc, root, v);
        }
    }
    void clear(node_t *&root) { _btree.clear(root); }

    void encode(binary_t &bin, byte_t *source, size_t size) {
        // align to LSB
        std::string buf;
        byte_t *p = nullptr;
        size_t i = 0;
        maphint<uint8, std::string> hint(_table);

        size_t remains = _totalbits % 8;

        for (p = source, i = 0; i < size; i++) {
            std::string code;
            hint.find(p[i], &code);
            buf += code;

            if (remains) {
                if (buf.size() > remains) {
                    uint8 b = 0;
                    for (size_t i = 0; i < remains; i++) {
                        if ('1' == buf[i]) {
                            b += (1 << (7 - i - remains));
                        }
                    }
                    bin.insert(bin.end(), b);
                    buf.erase(0, remains);

                    remains = 0;
                }
            }

            while (buf.size() >= 8) {
                uint8 b = 0;
                for (size_t i = 0; i < 8; i++) {
                    if ('1' == buf[i]) {
                        b += (1 << (7 - i));
                    }
                }
                bin.insert(bin.end(), b);
                buf.erase(0, 8);
            }
        }
    }
    void encode(stream_t *s, byte_t *source, size_t size) {
        // align to MSB
        byte_t *p = nullptr;
        size_t i = 0;
        maphint<uint8, std::string> hint(_table);
        for (p = source, i = 0; i < size; i++) {
            std::string code;
            hint.find(p[i], &code);
            s->printf("%s ", code.c_str());
        }
    }

   protected:
    void build(typename btree_t::node_t *&p) {
        if (p) {
            if (p->_left) {
                build(p->_left);
            }
            if (p->_right) {
                build(p->_right);
            }
            typename map_t::iterator iter = _m.find(p->_key);
            if (_m.end() != iter) {
                typename btree_t::node_t *t = iter->second;

                _btree.clear(p);
                p = t;
                _m.erase(iter);
            }
        }
    }
    void infer(hcode &hc, typename btree_t::node_t *t, infer_visitor v) {
        if (t) {
            hc.depth++;

            hc.code += "0";
            infer(hc, t->_left, v);
            hc.code.pop_back();

            bool use = false;
            uint8 symbol = 0;
            size_t weight = 0;
            v(t->_key, use, symbol, weight, hc.code);
            if (use) {
                _table.insert(std::make_pair(symbol, hc.code));
                _totalbits += (weight * hc.code.size());
            }

            hc.code += "1";
            infer(hc, t->_right, v);
            hc.code.pop_back();

            hc.depth--;
        }
    }
    size_t sizeof_table() {
        size_t ret = 0;
        for (auto item : _table) {
        }
        return ret;
    }

   private:
    measure_tree_t _measure;
    btree_t _btree;
    map_t _m;
    table_t _table;
    size_t _totalbits;
};

}  // namespace hotplace

#endif
