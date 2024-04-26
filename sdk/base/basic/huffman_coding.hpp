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

#ifndef __HOTPLACE_SDK_BASE_BASIC_HUFFMAN__
#define __HOTPLACE_SDK_BASE_BASIC_HUFFMAN__

#include <deque>
#include <functional>
#include <map>
#include <sdk/base/basic/tree.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/stl.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

/*
 * @brief   huffman codes
 * @refer   Data Structures and Algorithm Analysis in C++ - 10.1.2 Huffman Codes
 *          Data Structures & Algorithms in C++ - 12.4.1 The Huffman-Coding Algorithm
 *          https://asecuritysite.com/calculators/huff
 * @sample
 *          huffman_coding huff;
 *          huff.load(sample).learn().infer();
 */

template <typename T>
struct t_comparator_base {
    friend bool operator<(const T &lhs, const T &rhs) { return lhs < rhs; }
};

template <typename T>
struct t_type_comparator : t_comparator_base<T> {
    bool operator()(const T &lhs, const T &rhs) { return lhs.symbol < rhs.symbol; }
};

class huffman_coding {
   private:
    struct hc_t {
        uint8 symbol;
        size_t weight;
        uint32 flags;

        hc_t() : symbol(0), weight(0), flags(0) {}
        hc_t(uint8 b) : symbol(b), weight(0), flags(0) {}
        hc_t(uint8 b, size_t f) : symbol(b), weight(f), flags(0) {}
        hc_t(const hc_t &rhs) : symbol(rhs.symbol), weight(rhs.weight), flags(rhs.flags) {}
        bool operator<(const hc_t &rhs) const { return symbol < rhs.symbol; }
    };
    struct hc_comparator : t_comparator_base<hc_t> {
        bool operator()(const hc_t &lhs, const hc_t &rhs) const {
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
    struct hc_temp {
        size_t depth;
        std::string code;

        hc_temp() : depth(0) {}
    };
    typedef t_btree<hc_t> measure_tree_t;
    typedef t_btree<hc_t, hc_comparator> btree_t;
    typedef std::map<hc_t, typename btree_t::node_t *, hc_comparator> map_t;
    typedef std::pair<typename map_t::iterator, bool> map_pib_t;
    typedef std::map<uint8, std::string> codetable_t;
    typedef typename btree_t::node_t node_t;

   public:
    typedef typename std::function<void(hc_t const &t)> const_visitor;
    typedef typename std::function<void(hc_t &t)> visitor;
    typedef typename std::function<void(hc_t &t, const hc_t &lhs, const hc_t &rhs)> learn_visitor;

    huffman_coding() {}
    ~huffman_coding() {
        _measure.clear();
        _btree.clear();
        _m.clear();
        _codetable.clear();
    }

    void reset() { _measure.clear(); }

    huffman_coding &operator<<(const char *s) { return load(s); }
    huffman_coding &load(const char *s) {
        // count
        if (s) {
            for (const char *p = s; *p; p++) {
                _measure.insert(hc_t((uint8)*p), [](hc_t &t) -> void { t.weight++; });
            }
        }
        return *this;
    }

    huffman_coding &learn() {
        _btree.clear();
        _m.clear();
        _codetable.clear();

        _measure.for_each([&](hc_t const &t) -> void { _btree.insert(t); });

        while (_btree.size() > 1) {
            hc_t k;
            hc_t k_lhs;
            hc_t k_rhs;

            typename btree_t::node_t *l = _btree.clone_nocascade(_btree.first());
            k_lhs = l->_key;
            _btree.remove(l->_key);

            typename btree_t::node_t *r = _btree.clone_nocascade(_btree.first());
            k_rhs = r->_key;
            _btree.remove(r->_key);

            k.symbol = k_lhs.symbol;
            k.weight = k_lhs.weight + k_rhs.weight;
            k.flags = 1;  // merged

            typename btree_t::node_t *newone = _btree.insert(k, _btree._root);  // merged

            map_pib_t pib = _m.insert(std::make_pair(k, _btree.clone_nocascade(newone)));
            pib.first->second->_left = l;
            pib.first->second->_right = r;
        }
        return *this;
    }

    huffman_coding &infer() {
        huffman_coding::node_t *root = nullptr;
        build(&root);

        if (root) {
            hc_temp hc;
            infer(hc, root);

            clear(root);
        }

        return *this;
    }

    void encode(binary_t &bin, byte_t *source, size_t size) {
        return_t ret = errorcode_t::success;
        std::string buf;
        std::string code;
        size_t totalbits = 0;
        byte_t *p = nullptr;
        size_t i = 0;
        maphint<uint8, std::string> hint(_codetable);

#if 0
        // align to LSB

        for (p = source, i = 0; i < size; i++) {
            ret = hint.find(p[i], &code);
            if (errorcode_t::success != ret) {
                ret = errorcode_t::bad_data;
                break;
            }
            totalbits += code.size();
        }

        if (errorcode_t::success == ret) {
            size_t remains = totalbits % 8;

            for (p = source, i = 0; i < size; i++) {
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
#else
        // align to MSB
        for (p = source, i = 0; i < size; i++) {
            std::string code;
            hint.find(p[i], &code);
            buf += code;

            while (buf.size() >= 8) {
                uint8 b = 0;
                for (int i = 0; i < 8; i++) {
                    if ('1' == buf[i]) {
                        b += (1 << (7 - i));
                    }
                }
                bin.insert(bin.end(), b);
                buf.erase(0, 8);
            }
        }
        {
            uint8 b = 0;
            size_t remains = buf.size();
            for (int i = 0; i < remains; i++) {
                if ('1' == buf[i]) {
                    b += (1 << (7 - i));
                }
            }
            bin.insert(bin.end(), b);
            buf.erase(0, remains);
        }
#endif
    }
    void encode(stream_t *s, byte_t *source, size_t size) {
        // align to MSB
        byte_t *p = nullptr;
        size_t i = 0;
        maphint<uint8, std::string> hint(_codetable);
        for (p = source, i = 0; i < size; i++) {
            std::string code;
            hint.find(p[i], &code);
            s->printf("%s ", code.c_str());
        }
    }

   protected:
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
    void clear(node_t *&root) { _btree.clear(root); }

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
    void infer(hc_temp &hc, typename btree_t::node_t *t) {
        if (t) {
            hc.depth++;

            hc.code += "0";
            infer(hc, t->_left);
            hc.code.pop_back();

            bool use = false;
            uint8 symbol = 0;

            if (0 == t->_key.flags) {
                _codetable.insert(std::make_pair(t->_key.symbol, hc.code));
            }

            hc.code += "1";
            infer(hc, t->_right);
            hc.code.pop_back();

            hc.depth--;
        }
    }

   private:
    measure_tree_t _measure;
    btree_t _btree;
    map_t _m;
    codetable_t _codetable;
};

}  // namespace hotplace

#endif
