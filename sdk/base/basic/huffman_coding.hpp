/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   huffman_coding.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2024.04.25   Soo Han, Kim        study (codename.hotplace Revision 504)
 * 2026.05.25   Soo Han and Gemini  refactoring
 *
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_HUFFMANCODING__
#define __HOTPLACE_SDK_BASE_BASIC_HUFFMANCODING__

#include <deque>
#include <functional>
#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/nostd/btree.hpp>
#include <hotplace/sdk/base/nostd/range.hpp>
#include <hotplace/sdk/base/nostd/utility.hpp>
#include <hotplace/sdk/base/pattern/trie.hpp>
#include <map>

namespace hotplace {

enum huffman_coding_flags : uint32 {
    manual_decode = 0x01,
    stream_decode = 0x02,
};

/*
 * @brief   huffman codes
 * @refer   Data Structures and Algorithm Analysis in C++ - 10.1.2 Huffman Codes
 *          Data Structures & Algorithms in C++ - 12.4.1 The Huffman-Coding Algorithm
 *          https://asecuritysite.com/calculators/huff
 * @sample
 *          huffman_coding huff;
 *          // method.1 - learn huffman codes from stream
 *          huff.load(sample).learn().infer();
 *          // method.2 - load from pre-trained codes
 *          huff.imports(_h2hcodes);
 */

class huffman_coding {
   private:
    struct hc_t {
        uint8 symbol;
        size_t weight;
        uint32 flags;

        hc_t() : symbol(0), weight(0), flags(0) {}
        hc_t(uint8 b) : symbol(b), weight(0), flags(0) {}
        hc_t(uint8 b, size_t f) : symbol(b), weight(f), flags(0) {}

        hc_t(const hc_t& other) = default;
        hc_t(hc_t&& other) = default;

        hc_t& operator=(const hc_t& other) = default;
        hc_t& operator=(hc_t&& other) = default;

        friend bool operator<(const hc_t& lhs, const hc_t& rhs) { return lhs.symbol < rhs.symbol; }
    };
    struct hc_less {
        bool operator()(const hc_t& lhs, const hc_t& rhs) const {
            // tie is easy, but results is different ..
            if (lhs.weight != rhs.weight) {
                return (lhs.weight < rhs.weight);
            }
            if (lhs.flags < rhs.flags) {
                return true;
            }
            return lhs.symbol < rhs.symbol;
        }
    };
    struct hc_temp {
        size_t depth;
        std::string code;

        hc_temp() : depth(0) {}
    };
    struct hc_code {
        uint8 sym;
        const char* code;
    };

    typedef t_btree<hc_t> measure_tree_t;    // counting
    typedef t_btree<hc_t, hc_less> btree_t;  // by weight(frequency)
    typedef std::map<hc_t, typename btree_t::node_t*, hc_less> map_t;
    typedef std::map<uint8, std::string> codetable_t;
    typedef std::map<std::string, uint8> reverse_codetable_t;
    typedef typename btree_t::node_t node_t;

   public:
    typedef hc_code hc_code_t;

    huffman_coding();
    ~huffman_coding();

    void reset();

    /**
     * @example
     *          huffman.reset();
     *          huffman.load(stream1).load(stream2).load(stream3).learn().infer();
     */
    huffman_coding& operator<<(const char* s);
    huffman_coding& load(const char* s);
    huffman_coding& learn();
    huffman_coding& infer();

    /**
     * @brief   import pre-trained codes
     * @sample
     *          const huffman_coding::hc_code_t _h2hcodes[] = {
     *              { 1, "11111111111111111011000" },
     *              { 2, "1111111111111111111111100010" },
     *              // ...
     *              { 0, nullptr },
     *          };
     *
     *          huffman_coding huff;
     *          huff.imports(_h2hcodes);
     */
    huffman_coding& imports(const hc_code_t* table);
    huffman_coding& imports(const std::map<uint8, std::string>& m);
    /**
     * @brief   export hufman codes
     * @sample
     *          auto lambda_exports = [](uint8 sym, const char* code) -> void {
     *              printf("sym %c (0x%02x) %s (%zi)\n", isprint(sym) ? sym : '?', sym, code, strlen(code));
     *          };
     *          huffman_coding huff;
     *          huff.imports(_h2hcodes).exports(lambda_exports);
     */
    template <typename F>
    huffman_coding& exports(F fn) {
        for (auto item : _codetable) {
            fn(item.first, item.second.c_str());
        }
        return *this;
    }

    return_t expect(const char* source, size_t& size_expected) const;
    return_t expect(const char* source, size_t size, size_t& size_expected) const;
    return_t expect(const byte_t* source, size_t size, size_t& size_expected) const;

    /*
     * @brief   encode
     * @sample
     *          const char* sample = "www.example.com";
     *          binary_t bin;
     *          huff.encode(bin, (byte_t*)sample, strlen(sample));
     *          // f1 e3 c2 e5 f2 3a 6b a0 ab 90 f4 ff
     */
    template <typename T, typename std::enable_if<custom::encoder_stream_traits<T>::value, int>::type = 0>
    return_t encode(T& streambuf, const char* source, size_t size, bool usepad = true) const {
        return encode(streambuf, (byte_t*)source, size, usepad);
    }
    template <typename T, typename std::enable_if<custom::encoder_stream_traits<T>::value, int>::type = 0>
    return_t encode(T& streambuf, const byte_t* source, size_t size, bool usepad = true) const {
        typedef custom::encoder_stream_traits<T> traits;
        typedef typename traits::value_type value_type;
        return_t ret = errorcode_t::success;

        /**
         * RFC 7541 Appendix B.  Huffman Code
         * As the Huffman-encoded data doesn't always end at an octet boundary,
         * some padding is inserted after it, up to the next octet boundary.
         *
         * RFC 7541 5.2. String Literal Representation
         * As the Huffman-encoded data doesn't always end at an octet boundary,
         * some padding is inserted after it, up to the next octet boundary.  To
         * prevent this padding from being misinterpreted as part of the string
         * literal, the most significant bits of the code corresponding to the
         * EOS (end-of-string) symbol are used.
         *
         *  if min(code len in bits) >=  5 ... no problem while encode/decode
         *      huffman_coding huff;
         *      huff.imports(_h2hcodes);
         *      // EOS 256 111111111111111111111111111111 3fffffff [30]
         *  else min(code len in bits) < 5 ... ambiguous
         *      // A |1010  a [4]
         *      // B |1111  f [4]
         *      // 1010 1111 -> AB
         *      // 1010 pppp -> AB or A ?
         */

        if (nullptr == source) return errorcode_t::invalid_parameter;

        auto code_minsize = _range.getmin();
        auto code_maxsize = _range.getmax();

        usepad &= (code_minsize >= 5);  // overwrite usepad

        traits::preempt(streambuf, ((size * code_maxsize) + 7) / 8);

        value_type bit_buffer = 0;
        int bit_count = 0;

        for (size_t i = 0; i < size; ++i) {
            value_type sym = (value_type)source[i];
            const auto& cache = get_encode_cache(sym);
            auto bit_code = cache.bit_code;
            auto bit_len = cache.bit_len;

            for (int8 b = bit_len - 1; b >= 0; --b) {
                bit_buffer <<= 1;
                if ((bit_code >> b) & 1) bit_buffer |= 1;
                ++bit_count;

                if (8 == bit_count) {
                    traits::push(streambuf, bit_buffer);
                    bit_buffer = 0;
                    bit_count = 0;
                }
            }
        }
        if (bit_count > 0) {
            if (usepad) {
                bit_buffer = (bit_buffer << (8 - bit_count)) | ((1 << (8 - bit_count)) - 1);
            } else {
                bit_buffer <<= (8 - bit_count);
            }
            traits::push(streambuf, bit_buffer);
        }
        return ret;
    }

    /*
     * @brief   diag
     * @sample
     *          const char* sample = "www.example.com";
     *          basic_stream bs;
     *          huff.diag(bs, (byte_t*)sample, strlen(sample));
     *          printf("%s\n", bs.c_str());
     *
     */
    template <typename T, typename std::enable_if<custom::encoder_stream_traits<T>::value, int>::type = 0>
    return_t diag(T& streambuf, const char* source, size_t size) const {
        return diag(streambuf, (byte_t*)source, size);
    }
    template <typename T, typename std::enable_if<custom::encoder_stream_traits<T>::value, int>::type = 0>
    return_t diag(T& streambuf, const byte_t* source, size_t size) const {
        typedef custom::encoder_stream_traits<T> traits;
        // typedef typename traits::value_type value_type;
        return_t ret = errorcode_t::success;
        if (nullptr == source) {
            return errorcode_t::invalid_parameter;
        }
        const byte_t* p = nullptr;
        size_t i = 0;
        t_maphint_const<uint8, std::string> hint(_codetable);
        for (p = source, i = 0; i < size; i++) {
            std::string code;
            hint.find(p[i], &code);
            traits::append(streambuf, code.c_str());
            traits::append(streambuf, " ");
        }
        return ret;
    }
    /**
     * @brief   decode
     * @remarks constraints : min(code len in bits) >= 5
     *          to ignore set manual_decode
     *
     *          huff.imports(_h2hcodes);  // RFC 7541 Appendix B. Huffman Code
     *          huff.encode(...);
     *          huff.decode(...);
     */
    template <typename T, typename std::enable_if<custom::encoder_stream_traits<T>::value, int>::type = 0>
    return_t decode(T& streambuf, const byte_t* source, size_t size, uint32 flags = 0) const {
        return_t ret = errorcode_t::success;
        if (nullptr == source) {
            return errorcode_t::invalid_parameter;
        }

        size_t code_minsize = 0;
        code_minsize = _range.getmin();

        if (0 == (huffman_coding_flags::manual_decode & flags)) {
            if (code_minsize <= 4) {
                // see encode
                return errorcode_t::ambiguous;
            }
        }

        std::string que;
        ret = decoding(streambuf, que, source, size);
        if (errorcode_t::success != ret) {
            return ret;
        }

        for (char e : que) {
            if ('1' != e) {
                if (0 == (huffman_coding_flags::manual_decode & flags)) {
                    return errorcode_t::bad_data;
                }
                break;
            }
        }
        return ret;
    }
    /**
     * @brief   stream decoding
     */
    template <typename T, typename std::enable_if<custom::encoder_stream_traits<T>::value, int>::type = 0>
    return_t decoding(T& streambuf, std::string& que, const byte_t* source, size_t size) const {
        typedef custom::encoder_stream_traits<T> traits;
        typedef typename traits::value_type value_type;
        return_t ret = errorcode_t::success;
        if (nullptr == source) {
            return errorcode_t::invalid_parameter;
        }

        size_t code_minsize = 0;
        code_minsize = _range.getmin();

        if (que.size() < 64) {
            que.reserve(64);
        }

        auto lambda = [&]() -> void {
            while (que.size() >= code_minsize) {
                size_t pos = 0;
                int rc = _trie.scan(que.c_str(), que.size(), pos);  // scan first occurrence
                if (-1 == rc) break;

                traits::push(streambuf, (value_type)rc);
                que.erase(0, pos);
            }
        };

        lambda();

        for (size_t i = 0; i < size; ++i) {
            uint8 b = source[i];
            for (int n = 7; n >= 0; --n) {
                que.push_back((b & (1 << n)) ? '1' : '0');
            }

            lambda();
        }

        return ret;
    }

    /**
     * @brief   check min(code len in bits) >= 5
     */
    bool decodable();

    size_t sizeof_codetable();

    struct encode_cache_t {
        uint32 bit_code;
        uint8 bit_len;
    };
    inline const encode_cache_t& get_encode_cache(uint8 sym) const { return _encode_cache[sym >= 256 ? 0 : sym]; }

   protected:
    node_t* build(node_t** root = nullptr);
    void build(typename btree_t::node_t*& p);
    void infer(hc_temp& hc, typename btree_t::node_t* t);
    void dump();  // debug

    encode_cache_t _encode_cache[256 + 1];  // EOS (End of String)

    void build_cache(uint8 sym, const std::string code);

   private:
    measure_tree_t _measure;
    btree_t _btree;
    codetable_t _codetable;
    map_t _m;

    t_trie<char> _trie;
    t_sampling_range<size_t> _range;
};

}  // namespace hotplace

#endif
