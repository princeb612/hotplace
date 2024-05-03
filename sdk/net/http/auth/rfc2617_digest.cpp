/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base.hpp>
#include <sdk/crypto.hpp>
#include <sdk/io.hpp>
#include <sdk/net/http/auth/rfc2617_digest.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

rfc2617_digest::rfc2617_digest() {}

rfc2617_digest& rfc2617_digest::add(const char* data) {
    _stream << data;
    _sequence << data;
    return *this;
}

rfc2617_digest& rfc2617_digest::add(const std::string& data) {
    _stream << data;
    _sequence << data;
    return *this;
}

rfc2617_digest& rfc2617_digest::add(const basic_stream& data) {
    _stream << data;
    _sequence << data;
    return *this;
}

rfc2617_digest& rfc2617_digest::operator<<(const char* data) {
    _stream << data;
    _sequence << data;
    return *this;
}

rfc2617_digest& rfc2617_digest::operator<<(const std::string& data) {
    _stream << data;
    _sequence << data;
    return *this;
}

rfc2617_digest& rfc2617_digest::operator<<(const basic_stream& data) {
    _stream << data;
    _sequence << data;
    return *this;
}

rfc2617_digest& rfc2617_digest::digest(const std::string& algorithm) {
    openssl_digest dgst;
    std::string digest_value;

    // RFC 7616
    //      MD5, SHA-512-256, SHA-256
    //      MD5-sess, SHA-512-256-sess, SHA-256-sess
    std::map<std::string, std::string> algmap;
    algmap.insert(std::make_pair("MD5", "md5"));
    algmap.insert(std::make_pair("MD5-sess", "md5"));
    algmap.insert(std::make_pair("SHA-512-256", "sha2-512/256"));
    algmap.insert(std::make_pair("SHA-512-256-sess", "sha2-512/256"));
    algmap.insert(std::make_pair("SHA-256", "sha256"));
    algmap.insert(std::make_pair("SHA-256-sess", "sha256"));

    std::string hashalg;
    std::map<std::string, std::string>::iterator alg_iter = algmap.find(algorithm);
    if (algmap.end() != alg_iter) {
        hashalg = alg_iter->second;
    } else {
        hashalg = "md5";  // default
    }

    dgst.digest(hashalg.c_str(), _stream, digest_value, encoding_t::encoding_base16);
    _stream = digest_value;
    basic_stream temp;
    temp << "_H<" << algorithm << ">(";
    _sequence.insert(0, temp.data(), temp.size());
    _sequence.write(")", 1);

    return *this;
}

std::string rfc2617_digest::get() {
    std::string ret_value;
    ret_value = _stream.c_str();
    return ret_value;
}

std::string rfc2617_digest::get_sequence() {
    std::string ret_value;
    ret_value = _sequence.c_str();
    return ret_value;
}

rfc2617_digest& rfc2617_digest::clear() {
    _stream.clear();
    _sequence.clear();
    return *this;
}

}  // namespace net
}  // namespace hotplace
