/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          -dump : dump all keys
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void test_jwk_thumbprint() {
    print_text("JSON Web Key (JWK) Thumbprint");

    // return_t ret = errorcode_t::success;
    json_web_key jwk;
    json_web_signature jws;
    std::string sample;
    crypto_key key;
    binary_t pub1;
    binary_t pub2;
    binary_t priv;
    std::string buffer;
    std::string thumbprint;
    json_t* json_root = nullptr;
    binary_t hash_value;
    basic_stream bs;

    jwk.load_file(&key, key_ownspec, "rfc7638_3.jwk");
    key.for_each(dump_crypto_key, nullptr);

    const EVP_PKEY* pkey = key.any();
    key.get_public_key(pkey, pub1, pub2);

    _logger->writeln("x : %s", base16_encode(pub1).c_str());
    _logger->writeln("y : %s", base16_encode(pub2).c_str());

    json_root = json_object();
    json_object_set_new(json_root, "e", json_string(base64_encode(pub2, base64_encoding_t::base64url_encoding).c_str()));
    json_object_set_new(json_root, "kty", json_string("RSA"));
    json_object_set_new(json_root, "n", json_string(base64_encode(pub1, base64_encoding_t::base64url_encoding).c_str()));
    char* contents = json_dumps(json_root, JSON_COMPACT);
    if (contents) {
        buffer = contents;
        free(contents);
    }
    json_decref(json_root);

    // replace (buffer, " ", "");
    dump2("dump", buffer);
    dump_elem(buffer);

    hash_stream("sha256", (byte_t*)buffer.c_str(), buffer.size(), hash_value);
    thumbprint = base64_encode(hash_value, base64_encoding_t::base64url_encoding);

    const OPTION& option = _cmdline->value();
    if (option.verbose) {
        bs << "in lexicographic order : "
           << "\n"
           << buffer << "\n"
           << "hash : "
           << "\n"
           << base16_encode(hash_value) << "\n"
           << "thumbprint :"
           << "\n"
           << thumbprint;
        _logger->writeln(bs);
    }

    // crv, kty, x, y
    // e, kty, n
    // k, kty

    sample = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
    bool result = (thumbprint == sample);
    _test_case.test(result ? errorcode_t::success : errorcode_t::internal_error, __FUNCTION__, "RFC 7638 3.1.  Example JWK Thumbprint Computation");
}
