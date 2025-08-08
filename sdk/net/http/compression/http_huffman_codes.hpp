/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_COMPRESSION_HTTP2HUFFMANCODES__
#define __HOTPLACE_SDK_NET_HTTP_COMPRESSION_HTTP2HUFFMANCODES__

#include <sdk/base/basic/huffman_coding.hpp>
#include <sdk/net/http/compression/http_header_compression.hpp>

namespace hotplace {
namespace net {

/*
 * @brief   RFC 7541 Appendix B. Huffman Code
 * @sample
 *          huffman_coding huff;
 *          huff.imports(_h2hcodes);
 */
extern const huffman_coding::hc_code_t _h2hcodes[];

}  // namespace net
}  // namespace hotplace

#endif
