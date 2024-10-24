/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * spec list
 *      qop=auth
 *      algorithm=MD5|MD5-sess|SHA-256|SHA-256-sess
 *      userhash
 * todo list
 *      qop=auth-int
 *      nextnonce
 */

#ifndef __HOTPLACE_SDK_NET_QUIC__
#define __HOTPLACE_SDK_NET_QUIC__

#include <map>
#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <sdk/io.hpp>
#include <sdk/net/types.hpp>

namespace hotplace {
using namespace io;
namespace net {

// RFC 9000 QUIC: A UDP-Based Multiplexed and Secure Transport
// RFC 9001 Using TLS to Secure QUIC

// OpenSSL 3.2~
// https://docs.openssl.org/master/man7/ossl-guide-quic-introduction/
// https://docs.openssl.org/master/man7/ossl-guide-quic-multi-stream/

// studying...

}  // namespace net
}  // namespace hotplace

#endif
