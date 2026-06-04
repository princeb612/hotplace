/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   huffman_coding.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2024.04.25   Soo Han, Kim        study (codename.hotplace Revision 504)
 * 2026.05.25   Soo Han and Gemini  refactoring
 */

#include <hotplace/sdk/base/basic/huffman_coding.hpp>
#include <hotplace/sdk/base/nostd/utility.hpp>
#include <hotplace/sdk/base/system/trace.hpp>

namespace hotplace {

huffman_coding::huffman_coding() {}

huffman_coding::~huffman_coding() { reset(); }

void huffman_coding::reset() {
    _measure.clear();
    _btree.clear();
    _codetable.clear();
    _trie.reset();
    _range.reset();
    memset(_encode_cache, 0, sizeof(_encode_cache));
}

huffman_coding& huffman_coding::operator<<(const char* s) { return load(s); }

huffman_coding& huffman_coding::load(const char* s) {
    // count
    if (s) {
        auto hook = [](hc_t& t) -> void { t.weight++; };
        for (const char* p = s; *p; p++) {
            uint8 symbol = (uint8)*p;
            _measure.insert(hc_t(symbol), hook);
        }
    }
    return *this;
}

huffman_coding& huffman_coding::learn() {
    _btree.clear();
    _m.clear();
    _codetable.clear();
    _trie.reset();
    _range.reset();

    /**
     * _measure .. count(weight) by symbol, see hc_t::operator
     * _btree   .. merge by weight until (1 == size()), see hc_comparator::operator
     */

    auto lambda = [&](hc_t const& t) -> void { _btree.insert(t); };
    _measure.for_each(lambda);  // insert into _btree select * from _measure

    while (_btree.size() > 1) {
        hc_t k;
        hc_t k_lhs;
        hc_t k_rhs;

        typename btree_t::node_t* l = _btree.clone_nocascade(_btree.first());
        k_lhs = l->_key;
        _btree.remove(l->_key);

        typename btree_t::node_t* r = _btree.clone_nocascade(_btree.first());
        k_rhs = r->_key;
        _btree.remove(r->_key);

        k.symbol = k_lhs.symbol;
        k.weight = k_lhs.weight + k_rhs.weight;
        k.flags = 1;  // merged

        typename btree_t::node_t* newone = _btree.add(k);  // merged

        auto pib = _m.emplace(k, _btree.clone_nocascade(newone));
        pib.first->second->_left = l;
        pib.first->second->_right = r;
    }
    return *this;
}

huffman_coding& huffman_coding::infer() {
    huffman_coding::node_t* root = nullptr;
    build(&root);

    if (root) {
        hc_temp hc;
        // generate code .. left '0', right '1'
        infer(hc, root);

        _btree.clean(root);
    }

#if defined DEBUG
    dump();
#endif

    return *this;
}

void huffman_coding::infer(hc_temp& hc, typename btree_t::node_t* t) {
    if (t) {
        hc.depth++;

        hc.code += "0";
        infer(hc, t->_left);
        hc.code.pop_back();

        if (0 == t->_key.flags) {
            const auto& sym = t->_key.symbol;
            const auto& code = hc.code;
            size_t size = code.size();

            _codetable.emplace(sym, code);
            _trie.insert(code.c_str(), size, sym);
            _range.sampling(size);
            build_cache(sym, code);
        }

        hc.code += "1";
        infer(hc, t->_right);
        hc.code.pop_back();

        hc.depth--;
    }
}

huffman_coding::node_t* huffman_coding::build(node_t** root) {
    typename btree_t::node_t* p = nullptr;
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

void huffman_coding::build(typename btree_t::node_t*& p) {
    if (p) {
        if (p->_left) {
            build(p->_left);
        }
        if (p->_right) {
            build(p->_right);
        }
        typename map_t::iterator iter = _m.find(p->_key);
        if (_m.end() != iter) {
            typename btree_t::node_t* t = iter->second;

            _btree.clean(p);
            p = t;
            _m.erase(iter);
        }
    }
}

huffman_coding& huffman_coding::imports(const hc_code_t* table) {
    _codetable.clear();

    _trie.reset();
    _range.reset();

    for (size_t i = 0; table; i++) {
        const hc_code_t* item = table + i;
        if (nullptr == item->code) {
            break;
        }

        const auto& sym = item->sym;
        const auto& code = item->code;
        std::string code_string = code;
        size_t size = code_string.size();

        _trie.insert(code, size, sym);
        _range.sampling(size);
        build_cache(sym, code_string);
        _codetable.emplace(sym, std::move(code_string));
    }

#if defined DEBUG
    dump();
#endif

    return *this;
}

huffman_coding& huffman_coding::imports(const std::map<uint8, std::string>& m) {
    _codetable.clear();

    _trie.reset();
    _range.reset();

    for (const auto& item : m) {
        const auto& sym = item.first;
        const auto& code = item.second;
        size_t size = code.size();

        _codetable.emplace(sym, code);
        _trie.insert(code.c_str(), size, sym);
        _range.sampling(size);
        build_cache(sym, code);
    }

#if defined DEBUG
    dump();
#endif

    return *this;
}

return_t huffman_coding::expect(const char* source, size_t& size_expected) const {
    return_t ret = errorcode_t::success;
    __try2 {
        size_expected = 0;

        if (nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = expect((byte_t*)source, strlen(source), size_expected);
    }
    __finally2 {}
    return ret;
}

return_t huffman_coding::expect(const char* source, size_t size, size_t& size_expected) const {
    return_t ret = errorcode_t::success;
    __try2 {
        size_expected = 0;

        if (nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = expect((byte_t*)source, size, size_expected);
    }
    __finally2 {}
    return ret;
}

return_t huffman_coding::expect(const byte_t* source, size_t size, size_t& size_expected) const {
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

        size_t i = 0;
        const byte_t* p = source;
        for (i = 0; i < size; i++) {
            auto iter = _codetable.find(p[i]);
            const std::string& code = iter->second;
            sum += code.size();
        }

        /**
         * bits to bytes
         *
         * align (2^n) | (x + (align-1)) & ~(align-1) | output                      |
         *      4      | (x + 3) & ~3                 | 1..4 -> 4, 5..8 -> 8, ...   |
         *      8      | (x + 7) & ~7                 | 1..8 -> 8, 9..16 -> 16, ... |
         */
        size_expected = ((sum + 7) & ~7) >> 3;
    }
    __finally2 {}
    return ret;
}

bool huffman_coding::decodable() { return (_range.getmin() > 4) ? true : false; }

size_t huffman_coding::sizeof_codetable() { return _codetable.size(); }

void huffman_coding::dump() {
#if defined DEBUG
    if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_debug)) {
        trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
            dbs.println("- huffman coding table");
            auto lambda_exports = [&](uint8 sym, const char* code) -> void {
                dbs.println(R"(  - sym %c (0x%02x) code : "%s" (len %zi))", isprint(sym) ? sym : '?', sym, code, strlen(code));
            };
            exports(lambda_exports);
        });
    }
#endif
}

void huffman_coding::build_cache(uint8 sym, const std::string code) {
    uint32 bit_code = 0;
    for (char ch : code) {
        bit_code <<= 1;
        if (ch == '1') bit_code |= 1;
    }

    encode_cache_t& cache_item = _encode_cache[sym];
    cache_item.bit_code = bit_code;
    cache_item.bit_len = static_cast<uint8>(code.size());
}

}  // namespace hotplace
