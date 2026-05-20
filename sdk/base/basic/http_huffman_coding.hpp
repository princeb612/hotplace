/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   http_huffman_coding.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_HTTPHUFFMANCODING__
#define __HOTPLACE_SDK_BASE_BASIC_HTTPHUFFMANCODING__

#include <hotplace/sdk/base/basic/huffman_coding.hpp>

namespace hotplace {

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

}  // namespace hotplace

#endif
