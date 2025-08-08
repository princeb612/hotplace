/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_COMPRESSION_HTTP2HUFFMANCODING__
#define __HOTPLACE_SDK_NET_HTTP_COMPRESSION_HTTP2HUFFMANCODING__

#include <sdk/base/basic/huffman_coding.hpp>
#include <sdk/net/http/compression/http_static_table.hpp>

namespace hotplace {
namespace net {

/*
 * @brief   RFC 7541 Appendix B. Huffman Code
 * @sample
 *          huffman_coding huff;
 *          huff.imports(_h2hcodes);
 */
class http_huffman_coding : public huffman_coding {
   public:
    static http_huffman_coding* get_instance();

   protected:
    http_huffman_coding();

    virtual void load();

   private:
    critical_section _lock;
    static http_huffman_coding _instance;
};

}  // namespace net
}  // namespace hotplace

#endif
