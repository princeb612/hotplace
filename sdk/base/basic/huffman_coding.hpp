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
#include <sdk/base/basic/types.hpp>
#include <sdk/base/nostd/tree.hpp>

namespace hotplace {

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
    struct hc_code {
        uint8 sym;
        const char *code;
    };

    typedef t_btree<hc_t> measure_tree_t;
    typedef t_btree<hc_t, hc_comparator> btree_t;
    typedef std::map<hc_t, typename btree_t::node_t *, hc_comparator> map_t;
    typedef std::pair<typename map_t::iterator, bool> map_pib_t;
    typedef std::map<uint8, std::string> codetable_t;
    typedef std::map<std::string, uint8> reverse_codetable_t;

    typedef typename btree_t::node_t node_t;
    typedef typename std::function<void(hc_t const &t)> const_visitor;
    typedef typename std::function<void(hc_t &t)> visitor;
    typedef typename std::function<void(hc_t &t, const hc_t &lhs, const hc_t &rhs)> learn_visitor;

   public:
    typedef hc_code hc_code_t;

    huffman_coding();
    ~huffman_coding();

    void reset();

    huffman_coding &operator<<(const char *s);
    huffman_coding &load(const char *s);
    huffman_coding &learn();
    huffman_coding &infer();

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
    huffman_coding &imports(const hc_code_t *table);
    /**
     * @brief   export hufman codes
     * @sample
     *          huffman_coding huff;
     *          huff.imports(_h2hcodes).exports(
     *              [](uint8 sym, const char* code) -> void { printf("sym %c (0x%02x) %s (%zi)\n", isprint(sym) ? sym : '?', sym, code, strlen(code)); });
     */
    huffman_coding &exports(std::function<void(uint8, const char *)> v);

    return_t expect(const char *source, size_t &size_expected) const;
    return_t expect(const char *source, size_t size, size_t &size_expected) const;
    return_t expect(const byte_t *source, size_t size, size_t &size_expected) const;

    /*
     * @brief   encode
     * @sample
     *          const char* sample = "www.example.com";
     *          binary_t bin;
     *          huff.encode(bin, (byte_t*)sample, strlen(sample));
     *          // f1 e3 c2 e5 f2 3a 6b a0 ab 90 f4 ff
     */
    return_t encode(binary_t &bin, const char *source, size_t size, bool usepad = true) const;
    return_t encode(binary_t &bin, const byte_t *source, size_t size, bool usepad = true) const;
    /*
     * @brief   encode
     * @sample
     *          const char* sample = "www.example.com";
     *          basic_stream bs;
     *          huff.encode(&bs, (byte_t*)sample, strlen(sample));
     *          printf("%s\n", bs.c_str());
     *
     */
    return_t encode(stream_t *stream, const char *source, size_t size) const;
    return_t encode(stream_t *stream, const byte_t *source, size_t size) const;
    /**
     * @brief   decode
     * @remarks constraints : min(code len in bits) >= 5
     *
     *          huff.imports(_h2hcodes);  // RFC 7541 Appendix B. Huffman Code
     *          huff.encode(...);
     *          huff.decode(...);
     */
    return_t decode(stream_t *stream, const byte_t *source, size_t size) const;

    /**
     * @brief   check min(code len in bits) >= 5
     */
    bool decodable();

    size_t sizeof_codetable();

   protected:
    node_t *build(node_t **root = nullptr);
    void build(typename btree_t::node_t *&p);
    void infer(hc_temp &hc, typename btree_t::node_t *t);

   private:
    measure_tree_t _measure;
    btree_t _btree;
    map_t _m;
    codetable_t _codetable;
    reverse_codetable_t _reverse_codetable;
};

}  // namespace hotplace

#endif
