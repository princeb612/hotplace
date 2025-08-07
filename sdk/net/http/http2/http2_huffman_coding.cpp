/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/http2/http2_huffman_codes.hpp>
#include <sdk/net/http/http2/http2_huffman_coding.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http2_huffman_coding http2_huffman_coding::_instance;

http2_huffman_coding* http2_huffman_coding::get_instance() {
    _instance.load();
    return &_instance;
}

http2_huffman_coding::http2_huffman_coding() : huffman_coding() {}

void http2_huffman_coding::load() {
    if (0 == sizeof_codetable()) {
        critical_section_guard guard(_lock);
        if (0 == sizeof_codetable()) {
            // RFC 7541 Appendix B. Huffman Code
            imports(_h2hcodes);
        }
    }
}

}  // namespace net
}  // namespace hotplace
