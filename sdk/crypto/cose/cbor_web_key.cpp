/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/stl.hpp>
#include <hotplace/sdk/base/basic/base16.hpp>
#include <hotplace/sdk/base/basic/base64.hpp>
#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keyext.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/crypto/cose/cbor_web_key.hpp>
#include <hotplace/sdk/io/basic/json.hpp>
#include <hotplace/sdk/io/cbor/cbor_array.hpp>
#include <hotplace/sdk/io/cbor/cbor_data.hpp>
#include <hotplace/sdk/io/cbor/cbor_map.hpp>
#include <hotplace/sdk/io/cbor/cbor_publisher.hpp>
#include <hotplace/sdk/io/cbor/cbor_reader.hpp>
#include <hotplace/sdk/io/stream/buffer_stream.hpp>
#include <hotplace/sdk/io/stream/file_stream.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

cbor_web_key::cbor_web_key () : crypto_keyext ()
{
    // do nothing
}

cbor_web_key::~cbor_web_key ()
{
    // do nothing
}

return_t cbor_web_key::load (crypto_key* crypto_key, const char* buffer, int flags)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == crypto_key || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin;
        bin = base16_decode (buffer);

        ret = load (crypto_key, &bin[0], bin.size (), flags);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_web_key::load (crypto_key* crypto_key, std::string const& buf, int flags)
{
    return load (crypto_key, buf.c_str (), flags);
}

typedef struct _cose_object_key {
    int type;
    int curve;
    std::string kid;
    std::map <int, binary_t> attrib;

    _cose_object_key () : type (0), curve (0)
    {
        // do nothing
    }
} cose_key_object;

return_t cbor_web_key::load (crypto_key* crypto_key, const byte_t* buffer, size_t size, int flags)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_reader reader;
        cbor_reader_context_t* handle = nullptr;
        cbor_object* root = nullptr;

        reader.open (&handle);
        reader.parse (handle, buffer, size);
        ret = reader.publish (handle, &root);
        reader.close (handle);

        ret = load (crypto_key, root);

        root->release ();
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_web_key::load (crypto_key* crypto_key, binary_t const& buffer, int flags)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == crypto_key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = load (crypto_key, &buffer[0], buffer.size (), flags);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_web_key::load (crypto_key* crypto_key, cbor_object* root, int flags)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == crypto_key || nullptr == root) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // cose_key_object::type 1 okp, 2 ec2, 3 rsa, 4 symm, 5 hss lms, 6 walnut
        // cose_key_object::curve 1 p256, 2 p384, 3 p521, 4 x25519, 5 x448, 6 Ed25519, 7 Ed448
        // 415 : NID_X9_62_prime256v1 (prime256v1)
        // 715 : NID_secp384r1 (secp384r1)
        // 716 : NID_secp521r1 (secp521r1)
        // 1034: NID_X25519
        // 1035: NID_X448
        // 1087: NID_ED25519
        // 1088: NID_ED448
        std::map <int, uint32> cose_nid_curve;
        cose_nid_curve.insert (std::make_pair (1, NID_X9_62_prime256v1));
        cose_nid_curve.insert (std::make_pair (2, NID_secp384r1));
        cose_nid_curve.insert (std::make_pair (3, NID_secp521r1));
        cose_nid_curve.insert (std::make_pair (4, NID_X25519));
        cose_nid_curve.insert (std::make_pair (5, NID_X448));
        cose_nid_curve.insert (std::make_pair (6, NID_ED25519));
        cose_nid_curve.insert (std::make_pair (7, NID_ED448));

        if (cbor_type_t::cbor_type_array == root->type ()) {
            const std::list <cbor_object*>& keys = ((cbor_array*) root)->accessor ();
            std::list <cbor_object*>::const_iterator iter;
            for (iter = keys.begin (); iter != keys.end (); iter++) {
                cbor_object* child = *iter;
                if (cbor_type_t::cbor_type_map == child->type ()) {
                    cose_key_object keyobj;
                    const std::list <cbor_pair*>& key_contents = ((cbor_map*) child)->accessor ();
                    std::list <cbor_pair*>::const_iterator contents_iter;
                    for (contents_iter = key_contents.begin (); contents_iter != key_contents.end (); contents_iter++) {
                        cbor_pair* pair = *contents_iter;
                        cbor_data* lhs = (cbor_data*) pair->left ();
                        cbor_data* rhs = (cbor_data*) pair->right ();
                        // (nullptr != lhs) && (nullptr != rhs)
                        if ((lhs->type () == rhs->type ()) && (cbor_type_t::cbor_type_data == lhs->type ())) {
                            int label = t_variant_to_int<int> (lhs->data ());
                            const variant_t& vt_rhs = rhs->data ();
                            if (2 == label) {           // kid
                                variant_string (rhs->data (), keyobj.kid);
                            } else if (1 == label) {    // kty
                                keyobj.type = t_variant_to_int<int> (vt_rhs);
                            } else if (-1 == label) {   // ec2 curve, symmetric k
                                if (TYPE_BINARY == vt_rhs.type) {
                                    // symm
                                    binary_t bin;
                                    variant_binary (rhs->data (), bin);
                                    keyobj.attrib.insert (std::make_pair (label, bin));
                                } else {
                                    // curve if okp, ec2
                                    keyobj.curve = t_variant_to_int<int> (vt_rhs);
                                }
                            } else if (label < -1) { // ec2 (-2 x, -3 y, -4 d), rsa (-1 n, -2 e, -3 d, ..., -12 ti)
                                binary_t bin;
                                variant_binary (rhs->data (), bin);
                                keyobj.attrib.insert (std::make_pair (label, bin));
                            }
                        }
                    }
                    maphint <int, binary_t> hint_key (keyobj.attrib);
                    if (1 == keyobj.type || 2 == keyobj.type) { // okp, ec2
                        uint32 nid = 0;
                        maphint <int, uint32> hint_nid (cose_nid_curve);
                        hint_nid.find (keyobj.curve, &nid);
                        binary_t x;
                        binary_t y;
                        binary_t d;
                        hint_key.find (-2, &x);
                        hint_key.find (-3, &y);
                        hint_key.find (-4, &d);
                        add_ec (crypto_key, keyobj.kid.c_str (), nullptr, nid, x, y, d);
                    } else if (3 == keyobj.type) { // rsa
                        binary_t n;
                        binary_t e;
                        binary_t d;
                        hint_key.find (-1, &n);
                        hint_key.find (-2, &e);
                        hint_key.find (-3, &d);
                        add_rsa (crypto_key, keyobj.kid.c_str (), nullptr, n, e, d);
                    } else if (4 == keyobj.type) { // symm
                        binary_t k;
                        hint_key.find (-1, &k);
                        add_oct (crypto_key, keyobj.kid.c_str (), nullptr, k);
                    }
                }
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_web_key::write (crypto_key* crypto_key, char* buf, size_t* buflen, int flags)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == crypto_key || nullptr == buflen) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t cbor;
        ret = write (crypto_key, cbor, flags);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = base16_encode (cbor, buf, buflen);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

typedef struct _cose_mapper_t {
    cbor_array* root;

    _cose_mapper_t () : root (nullptr)
    {
        // do nothing
    }
} cose_mapper_t;

void cwk_writer (crypto_key_object_t* key, void* param)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        if (nullptr == param) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose_mapper_t* mapper = (cose_mapper_t*) param;
        cbor_array* root = mapper->root;
        if (nullptr == root) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        std::string kid = key->kid;

        crypto_key_t kty;
        binary_t pub1;
        binary_t pub2;
        binary_t priv;

        ret = crypto_key::get_key (key->pkey, 1, kty, pub1, pub2, priv);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        cbor_map* keynode = nullptr;
        __try_new_catch (keynode, new cbor_map (), ret, __leave2);

        cose_key_t cose_kty = advisor->ktyof (kty);
        *keynode << new cbor_pair (1, new cbor_data (cose_kty)); // kty
        if (kid.size ()) {
            *keynode << new cbor_pair (2, new cbor_data (convert (kid)));
        }

        if (crypto_key_t::kty_ec == kty || crypto_key_t::kty_okp == kty) {
            uint32 nid = 0;
            cose_ec_curve_t cose_curve = cose_ec_curve_t::cose_ec_unknown;

            nidof_evp_pkey (key->pkey, nid);
            cose_curve = advisor->curveof (nid);

            *keynode    << new cbor_pair (-1, new cbor_data (cose_curve))   // curve
                        << new cbor_pair (-2, new cbor_data (pub1));        // x

            // NID_secp521r1 521 = (65*8) + 1 => 66bytes => 132 base16 encoding bytes
            // 0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad
            // wo trailing 00
            //   72992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad

            if (crypto_key_t::kty_ec == kty) {
                *keynode << new cbor_pair (-3, new cbor_data (pub2)); // y
            }
            if (priv.size ()) {
                *keynode << new cbor_pair (-4, new cbor_data (priv)); // d
            }
        } else if (crypto_key_t::kty_hmac == kty) {
            *keynode << new cbor_pair (-1, new cbor_data (priv));       // k
        } else if (crypto_key_t::kty_rsa == kty) {
            *keynode    << new cbor_pair (-1, new cbor_data (pub1))     // n
                        << new cbor_pair (-2, new cbor_data (pub2));    // e
            if (priv.size ()) {
                *keynode << new cbor_pair (-3, new cbor_data (priv));   // d
            }
        }

        *root << keynode;
    }
    __finally2
    {
        // do nothing
    }
}

return_t cbor_web_key::write (crypto_key* crypto_key, std::string& buf, int flags)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        binary_t cbor;
        ret = write (crypto_key, cbor, flags);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        base16_encode (cbor, buf);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_web_key::write (crypto_key* crypto_key, binary_t& cbor, int flags)
{
    return_t ret = errorcode_t::success;
    cbor_object* root = nullptr;

    __try2
    {
        if (nullptr == crypto_key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = write (crypto_key, &root, flags);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        cbor_publisher publisher;
        ret = publisher.publish (root, &cbor);
    }
    __finally2
    {
        if (root) {
            root->release ();
        }
    }
    return ret;
}

return_t cbor_web_key::write (crypto_key* crypto_key, cbor_object** root, int flags)
{
    return_t ret = errorcode_t::success;
    cbor_array* cbor_root = nullptr;

    __try2
    {
        if (nullptr == crypto_key || nullptr == root) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch (cbor_root, new cbor_array (), ret, __leave2);

        cose_mapper_t mapper;
        mapper.root = cbor_root;

        crypto_key->for_each (cwk_writer, &mapper);

        *root = cbor_root;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_web_key::diagnose (crypto_key* crypto_key, stream_t* stream, int flags)
{
    return_t ret = errorcode_t::success;
    cbor_object* root = nullptr;

    __try2
    {
        if (nullptr == crypto_key || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        stream->clear ();

        ret = write (crypto_key, &root, flags);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        cbor_publisher publisher;

        publisher.publish (root, stream);
    }
    __finally2
    {
        if (root) {
            root->release ();
        }
    }
    return ret;
}

return_t cbor_web_key::load_file (crypto_key* crypto_key, const char* file, int flags)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == crypto_key || nullptr == file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        file_stream fs;
        ret = fs.open (file);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        fs.begin_mmap ();
        ret = load (crypto_key, (byte_t*) fs.data (), fs.size (), flags);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_web_key::write_file (crypto_key* crypto_key, const char* file, int flags)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == crypto_key || nullptr == file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        file_stream fs;
        ret = fs.open (file, filestream_flag_t::open_write);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        fs.truncate (0);

        binary_t cbor;
        write (crypto_key, cbor, flags);
        fs.write (&cbor[0], cbor.size ());
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

}
}  // namespace
