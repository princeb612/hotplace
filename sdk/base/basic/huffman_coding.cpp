/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.12   Soo Han, Kim        CBOR (codename.hotplace)
 */

#include <sdk/base/basic/huffman_coding.hpp>

namespace hotplace {

huffman_coding::huffman_coding() {}

huffman_coding::~huffman_coding() {
    _measure.clear();
    _btree.clear();
    _m.clear();
    _codetable.clear();
    _reverse_codetable.clear();
}

void huffman_coding::reset() { _measure.clear(); }

huffman_coding &huffman_coding::operator<<(const char *s) { return load(s); }

huffman_coding &huffman_coding::load(const char *s) {
    // count
    if (s) {
        for (const char *p = s; *p; p++) {
            _measure.insert(hc_t((uint8)*p), [](hc_t &t) -> void { t.weight++; });
        }
    }
    return *this;
}

huffman_coding &huffman_coding::learn() {
    _btree.clear();
    _m.clear();
    _codetable.clear();
    _reverse_codetable.clear();

    // _measure .. count(weight) by symbol, see hc_t::operator
    // _btree   .. merge by weight until (1 == size()), see hc_comparator::operator

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

        typename btree_t::node_t *newone = _btree.add(k);  // merged

        map_pib_t pib = _m.insert(std::make_pair(k, _btree.clone_nocascade(newone)));
        pib.first->second->_left = l;
        pib.first->second->_right = r;
    }
    return *this;
}

huffman_coding &huffman_coding::infer() {
    huffman_coding::node_t *root = nullptr;
    build(&root);

    if (root) {
        hc_temp hc;
        // generate code .. left '0', right '1'
        infer(hc, root);

        _btree.clean(root);
    }

    return *this;
}

huffman_coding &huffman_coding::imports(const hc_code_t *table) {
    _codetable.clear();
    _reverse_codetable.clear();

    for (size_t i = 0; table; i++) {
        const hc_code_t *item = table + i;
        if (nullptr == item->code) {
            break;
        }
        _codetable.insert(std::make_pair(item->sym, item->code));
        _reverse_codetable.insert(std::make_pair(item->code, item->sym));
    }

    return *this;
}

huffman_coding &huffman_coding::exports(std::function<void(uint8, const char *)> v) {
    for (auto item : _codetable) {
        v(item.first, item.second.c_str());
    }
    return *this;
}

return_t huffman_coding::expect(const char *source, size_t &size_expected) {
    return_t ret = errorcode_t::success;
    __try2 {
        size_expected = 0;

        if (nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = expect((byte_t *)source, strlen(source), size_expected);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t huffman_coding::expect(const char *source, size_t size, size_t &size_expected) {
    return_t ret = errorcode_t::success;
    __try2 {
        size_expected = 0;

        if (nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = expect((byte_t *)source, size, size_expected);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t huffman_coding::expect(const byte_t *source, size_t size, size_t &size_expected) {
    return_t ret = errorcode_t::success;
    __try2 {
        size_expected = 0;
        size_t sum = 0;

        if (nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (_codetable.empty()) {
            ret = errorcode_t::not_ready;
            __leave2;
        }

        t_maphint<uint8, std::string> hint(_codetable);
        size_t i = 0;
        const byte_t *p = source;
        for (i = 0; i < size; i++) {
            std::string code;
            hint.find(p[i], &code);
            sum += code.size();
        }

        // bits to bytes

        // align (2^n) | (x + (align-1)) & ~(align-1) | output                      |
        //      4      | (x + 3) & ~3                 | 1..4 -> 4, 5..8 -> 8, ...   |
        //      8      | (x + 7) & ~7                 | 1..8 -> 8, 9..16 -> 16, ... |
        size_expected = ((sum + 7) & ~7) >> 3;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t huffman_coding::encode(binary_t &bin, const char *source, size_t size, bool usepad) { return encode(bin, (byte_t *)source, size, usepad); }

return_t huffman_coding::encode(binary_t &bin, const byte_t *source, size_t size, bool usepad) {
    return_t ret = errorcode_t::success;
    std::string buf;
    std::string code;
    size_t totalbits = 0;
    const byte_t *p = nullptr;
    size_t i = 0;
    t_maphint<uint8, std::string> hint(_codetable);

    // RFC 7541 Appendix B.  Huffman Code
    // As the Huffman-encoded data doesn't always end at an octet boundary,
    // some padding is inserted after it, up to the next octet boundary.

    // RFC 7541 5.2. String Literal Representation
    // As the Huffman-encoded data doesn't always end at an octet boundary,
    // some padding is inserted after it, up to the next octet boundary.  To
    // prevent this padding from being misinterpreted as part of the string
    // literal, the most significant bits of the code corresponding to the
    // EOS (end-of-string) symbol are used.

    //  if min(code len in bits) >=  5 ... no problem while encode/decode
    //      huffman_coding huff;
    //      huff.imports(_h2hcodes);
    //      // EOS 256 111111111111111111111111111111 3fffffff [30]
    //  else min(code len in bits) < 5 ... ambiguous
    //      // A |1010  a [4]
    //      // B |1111  f [4]
    //      // 1010 1111 -> AB
    //      // 1010 pppp -> AB or A ?

    __try2 {
        if (nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (_reverse_codetable.empty()) {
            ret = errorcode_t::not_ready;
            __leave2;
        }

        size_t code_msize = _reverse_codetable.begin()->first.size();
        usepad &= (code_msize >= 5);  // overwrite usepad

        // align to MSB
        for (p = source, i = 0; i < size; i++) {
            std::string code;
            hint.find(p[i], &code);
            buf += code;

            if (usepad) {
                if (i == (size - 1)) {
                    size_t mod = (buf.size() % 8);
                    if (mod) {
                        size_t padsize = 8 - mod;
                        while (padsize--) {
                            buf += '1';
                        }
                    }
                }
            }

            while (buf.size() >= 8) {
                uint8 b = 0;
                for (int n = 0; n < 8; n++) {
                    if ('1' == buf[n]) {
                        b |= (1 << (7 - n));
                    }
                }
                bin.insert(bin.end(), b);
                buf.erase(0, 8);
            }
        }
        if (false == usepad) {
            size_t remains = buf.size();
            if (remains) {
                uint8 b = 0;

                for (int i = 0; i < remains; i++) {
                    if ('1' == buf[i]) {
                        b |= (1 << (7 - i));
                    }
                }
                bin.insert(bin.end(), b);
                buf.erase(0, remains);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t huffman_coding::encode(stream_t *stream, const char *source, size_t size) { return encode(stream, (byte_t *)source, size); }

return_t huffman_coding::encode(stream_t *stream, const byte_t *source, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream || nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        // align to MSB
        const byte_t *p = nullptr;
        size_t i = 0;
        t_maphint<uint8, std::string> hint(_codetable);
        for (p = source, i = 0; i < size; i++) {
            std::string code;
            hint.find(p[i], &code);
            stream->printf("%s ", code.c_str());
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t huffman_coding::decode(stream_t *stream, const byte_t *source, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == stream) || (nullptr == source)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (_reverse_codetable.empty()) {
            ret = errorcode_t::not_ready;
            __leave2;
        }

        size_t code_msize = _reverse_codetable.begin()->first.size();
        if (code_msize <= 4) {
            // see encode
            ret = errorcode_t::insufficient;
            __leave2;
        }

        std::string que;
        std::string token;

        for (size_t i = 0; i < size; i++) {
            byte_t b = source[i];
            for (int n = 7; n >= 0; n--) {
                que += ((b & (1 << n)) ? '1' : '0');
            }

            while (que.size() >= code_msize) {
                int count = 0;
                for (size_t l = code_msize; l <= que.size(); l++) {
                    token = que.substr(0, l);
                    std::map<std::string, uint8>::iterator iter = _reverse_codetable.find(token);
                    if (_reverse_codetable.end() != iter) {
                        stream->printf("%c", iter->second);
                        que.erase(0, l);
                        break;
                    } else {
                        count++;
                    }
                }
                if ((que.size() - code_msize + 1) == count) {
                    break;
                }
            }
        }

        for (auto e : que) {
            if ('1' != e) {
                ret = errorcode_t::bad_data;
                break;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

huffman_coding::node_t *huffman_coding::build(node_t **root) {
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

void huffman_coding::build(typename btree_t::node_t *&p) {
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

            _btree.clean(p);
            p = t;
            _m.erase(iter);
        }
    }
}

void huffman_coding::infer(hc_temp &hc, typename btree_t::node_t *t) {
    if (t) {
        hc.depth++;

        hc.code += "0";
        infer(hc, t->_left);
        hc.code.pop_back();

        if (0 == t->_key.flags) {
            _codetable.insert(std::make_pair(t->_key.symbol, hc.code));
            _reverse_codetable.insert(std::make_pair(hc.code, t->_key.symbol));
        }

        hc.code += "1";
        infer(hc, t->_right);
        hc.code.pop_back();

        hc.depth--;
    }
}

bool huffman_coding::decodable() {
    bool ret = false;
    __try2 {
        if (_reverse_codetable.empty()) {
            __leave2;
        }

        size_t code_msize = _reverse_codetable.begin()->first.size();
        if (code_msize <= 4) {
            __leave2;
        }

        ret = true;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace hotplace
