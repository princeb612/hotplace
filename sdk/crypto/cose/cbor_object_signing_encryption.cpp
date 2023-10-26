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

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/cose/cbor_object_encryption.hpp>
#include <sdk/crypto/cose/cbor_object_signing.hpp>
#include <sdk/crypto/cose/cbor_object_signing_encryption.hpp>
#include <sdk/io/cbor/cbor_array.hpp>
#include <sdk/io/cbor/cbor_data.hpp>
#include <sdk/io/cbor/cbor_encode.hpp>
#include <sdk/io/cbor/cbor_map.hpp>
#include <sdk/io/cbor/cbor_publisher.hpp>
#include <sdk/io/cbor/cbor_reader.hpp>
#include <sdk/io/cbor/concise_binary_object_representation.hpp>
#include <set>

namespace hotplace {
using namespace io;
namespace crypto {

cbor_object_signing_encryption::cbor_object_signing_encryption() {
    // do nothing
}

cbor_object_signing_encryption::~cbor_object_signing_encryption() {
    // do nothing
}

return_t cbor_object_signing_encryption::open(cose_context_t** handle) {
    return_t ret = errorcode_t::success;
    cose_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch(context, new cose_context_t, ret, __leave2);
        *handle = context;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::close(cose_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        clear_context(handle);
        delete handle;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::set(cose_context_t* handle, cose_param_t id, binary_t const& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        switch (id) {
            case cose_param_t::cose_external:
            case cose_param_t::cose_unsent_apu_id:
            case cose_param_t::cose_unsent_apu_nonce:
            case cose_param_t::cose_unsent_apu_other:
            case cose_param_t::cose_unsent_apv_id:
            case cose_param_t::cose_unsent_apv_nonce:
            case cose_param_t::cose_unsent_apv_other:
            case cose_param_t::cose_unsent_pub_other:
            case cose_param_t::cose_unsent_priv_other:
            case cose_param_t::cose_unsent_iv:
            case cose_param_t::cose_unsent_alg:
            case cose_param_t::cose_param_cek:
                handle->binarymap[id] = bin;
                break;
            default:
                ret = errorcode_t::request;
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::encrypt(cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    cbor_object_encryption cose_encryption;

    ret = cose_encryption.encrypt(handle, key, method, input, output);
    return ret;
}

return_t encrypt(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    cbor_object_encryption cose_encryption;

    ret = cose_encryption.encrypt(handle, key, methods, input, output);
    return ret;
}

return_t cbor_object_signing_encryption::decrypt(cose_context_t* handle, crypto_key* key, binary_t const& input, binary_t& output, bool& result) {
    return_t ret = errorcode_t::success;
    cbor_object_encryption cose_encryption;

    ret = cose_encryption.decrypt(handle, key, input, output, result);
    return ret;
}

return_t cbor_object_signing_encryption::sign(cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    cbor_object_signing cose_sign;

    ret = cose_sign.sign(handle, key, method, input, output);
    return ret;
}

return_t cbor_object_signing_encryption::sign(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    cbor_object_signing cose_sign;

    ret = cose_sign.sign(handle, key, methods, input, output);
    return ret;
}

return_t cbor_object_signing_encryption::verify(cose_context_t* handle, crypto_key* key, binary_t const& input, bool& result) {
    return_t ret = errorcode_t::success;
    cbor_object_signing cose_sign;

    ret = cose_sign.verify(handle, key, input, result);
    return ret;
}

return_t cbor_object_signing_encryption::clear_context(cose_context_t* handle) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        handle->clear();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

cbor_object_signing_encryption::composer::composer() {
    // do nothing
}
cbor_object_signing_encryption::composer::~composer() {
    // do nothing
}

return_t cbor_object_signing_encryption::composer::build_protected(cbor_data** object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_data* part_protected = nullptr;
        binary_t dummy;
        __try_new_catch(part_protected, new cbor_data(dummy), ret, __leave2);
        *object = part_protected;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::build_protected(cbor_data** object, cose_variantmap_t& input) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (0 == input.size()) {
            cbor_data* part_protected = nullptr;
            binary_t dummy;
            __try_new_catch(part_protected, new cbor_data(dummy), ret, __leave2);
            *object = part_protected;
        } else {
            binary_t bin_protected;
            cbor_map* part_protected = nullptr;

            __try_new_catch(part_protected, new cbor_map(), ret, __leave2);

            cose_variantmap_t::iterator map_iter;
            for (map_iter = input.begin(); map_iter != input.end(); map_iter++) {
                int key = map_iter->first;
                variant_t& value = map_iter->second;
                *part_protected << new cbor_pair(new cbor_data(key), new cbor_data(value));
            }

            build_protected(object, part_protected);

            part_protected->release();
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::build_protected(cbor_data** object, cose_variantmap_t& input, cose_orderlist_t& order) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (0 == input.size()) {
            cbor_data* part_protected = nullptr;
            binary_t dummy;
            __try_new_catch(part_protected, new cbor_data(dummy), ret, __leave2);
            *object = part_protected;
        } else {
            binary_t bin_protected;
            cbor_map* part_protected = nullptr;

            __try_new_catch(part_protected, new cbor_map(), ret, __leave2);

            cose_orderlist_t::iterator list_iter;
            for (list_iter = order.begin(); list_iter != order.end(); list_iter++) {
                int key = *list_iter;

                cose_variantmap_t::iterator map_iter = input.find(key);
                variant_t& value = map_iter->second;
                *part_protected << new cbor_pair(new cbor_data(key), new cbor_data(value));
            }

            build_protected(object, part_protected);

            part_protected->release();
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::build_protected(cbor_data** object, cbor_map* input) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object || nullptr == input) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin_protected;
        cbor_publisher publisher;
        publisher.publish(input, &bin_protected);

        *object = new cbor_data(bin_protected);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::build_unprotected(cbor_map** object) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_map* part_unprotected = nullptr;

        __try_new_catch(part_unprotected, new cbor_map(), ret, __leave2);

        *object = part_unprotected;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::build_unprotected(cbor_map** object, cose_variantmap_t& input) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_map* part_unprotected = nullptr;

        __try_new_catch(part_unprotected, new cbor_map(), ret, __leave2);

        cose_variantmap_t::iterator iter;
        for (iter = input.begin(); iter != input.end(); iter++) {
            int key = iter->first;
            variant_t& value = iter->second;
            *part_unprotected << new cbor_pair(new cbor_data(key), new cbor_data(value));
        }

        *object = part_unprotected;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::build_unprotected(cbor_map** object, cose_variantmap_t& input, cose_orderlist_t& order) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_map* part_unprotected = nullptr;

        __try_new_catch(part_unprotected, new cbor_map(), ret, __leave2);

        cose_orderlist_t::iterator list_iter;
        for (list_iter = order.begin(); list_iter != order.end(); list_iter++) {
            int key = *list_iter;

            cose_variantmap_t::iterator map_iter = input.find(key);
            variant_t& value = map_iter->second;
            *part_unprotected << new cbor_pair(new cbor_data(key), new cbor_data(value));
        }

        *object = part_unprotected;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::build_data(cbor_data** object, const char* payload) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object || nullptr == payload) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        __try_new_catch(*object, new cbor_data(convert(payload)), ret, __leave2);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::build_data(cbor_data** object, const byte_t* payload, size_t size) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        __try_new_catch(*object, new cbor_data(payload, size), ret, __leave2);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::build_data(cbor_data** object, binary_t const& payload) {
    return build_data(object, &payload[0], payload.size());
}

return_t cbor_object_signing_encryption::composer::build_data_b16(cbor_data** object, const char* str) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object || nullptr == str) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        __try_new_catch(*object, new cbor_data(base16_decode(str)), ret, __leave2);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::parse(cose_context_t* handle, binary_t const& input) {
    return_t ret = errorcode_t::success;
    return_t check = errorcode_t::success;
    cbor_reader reader;
    cbor_reader_context_t* reader_context = nullptr;
    cbor_object* root = nullptr;
    const char* kid = nullptr;
    std::set<bool> results;
    cbor_object_signing_encryption::composer composer;

    __try2 {
        clear_context(handle);

        ret = reader.open(&reader_context);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = reader.parse(reader_context, input);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = reader.publish(reader_context, &root);
        if (errorcode_t::success != ret) {
            __leave2_trace(ret);
        }

        if ((root->tagged()) && (cbor_type_t::cbor_type_array == root->type())) {
            // do nothing
        } else {
            ret = errorcode_t::request;
            __leave2_trace(ret);
        }

        int elemof_cbor = root->size();
        cbor_tag_t cbor_tag = root->tag_value();

        enum cose_message_type_t {
            cose_message_type_not_exist = 0,
            cose_message_type_protected = 1,
            cose_message_type_unprotected = 2,
            cose_message_type_payload = 3,
            cose_message_type_signature = 4,
            cose_message_type_items = 5,  // recipients, signatures
            cose_message_type_tag = 6,
        };
        typedef struct _cose_message_structure_t {
            cbor_tag_t cbor_tag;
            int elemof_cbor;
            cose_message_type_t typeof_item[5];
        } cose_message_structure_t;

        //                      [0]        [1]              [2]         [3]             [4]
        // cose_tag_encrypt     protected, unprotected_map, ciphertext, [+recipient]
        // cose_tag_encrypt0    protected, unprotected_map, ciphertext
        // cose_tag_mac         protected, unprotected_map, payload,    tag,            [+recipient]
        // cose_tag_mac0        protected, unprotected_map, payload,    tag
        // cose_tag_sign        protected, unprotected_map, payload,    [+signature]
        // cose_tag_sign1       protected, unprotected_map, payload,    signature
        cose_message_structure_t cose_message_structure_table[] = {
            {
                cose_tag_encrypt,
                4,
                {
                    cose_message_type_protected,
                    cose_message_type_unprotected,
                    cose_message_type_payload,
                    cose_message_type_items,
                },
            },
            {
                cose_tag_encrypt0,
                3,
                {
                    cose_message_type_protected,
                    cose_message_type_unprotected,
                    cose_message_type_payload,
                },
            },
            {
                cose_tag_mac,
                5,
                {
                    cose_message_type_protected,
                    cose_message_type_unprotected,
                    cose_message_type_payload,
                    cose_message_type_tag,
                    cose_message_type_items,
                },
            },
            {
                cose_tag_mac0,
                4,
                {
                    cose_message_type_protected,
                    cose_message_type_unprotected,
                    cose_message_type_payload,
                    cose_message_type_tag,
                },
            },
            {
                cose_tag_sign,
                4,
                {
                    cose_message_type_protected,
                    cose_message_type_unprotected,
                    cose_message_type_payload,
                    cose_message_type_items,
                },
            },
            {
                cose_tag_sign1,
                4,
                {
                    cose_message_type_protected,
                    cose_message_type_unprotected,
                    cose_message_type_payload,
                    cose_message_type_signature,
                },
            },
        };

        cose_message_structure_t* cose_message_map = nullptr;
        for (unsigned i = 0; i < RTL_NUMBER_OF(cose_message_structure_table); i++) {
            if (cose_message_structure_table[i].cbor_tag == cbor_tag) {
                cose_message_map = cose_message_structure_table + i;
                break;
            }
        }
        if (nullptr == cose_message_map) {
            ret = errorcode_t::bad_data;
            __leave2;
        }
        if (cose_message_map->elemof_cbor != elemof_cbor) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        handle->cbor_tag = cbor_tag;

        for (int i = 0; i < cose_message_map->elemof_cbor; i++) {
            int typeof_item = cose_message_map->typeof_item[i];
            cbor_object* item = (*(cbor_array*)root)[i];

            if (cose_message_type_protected == typeof_item) {
                cbor_data* cbor_protected = cbor_typeof<cbor_data>(item, cbor_type_t::cbor_type_data);
                if (nullptr == cbor_protected) {
                    ret = errorcode_t::bad_data;
                    break;
                }

                variant_binary(cbor_protected->data(), handle->body.bin_protected);
                composer.parse_binary(handle->body.bin_protected, handle->body.protected_map);
            } else if (cose_message_type_unprotected == typeof_item) {
                cbor_map* cbor_unprotected = cbor_typeof<cbor_map>(item, cbor_type_t::cbor_type_map);
                if (nullptr == cbor_unprotected) {
                    ret = errorcode_t::bad_data;
                    break;
                }

                composer.parse_map(cbor_unprotected, handle->body.unprotected_map);
            } else if (cose_message_type_payload == typeof_item) {
                cbor_data* cbor_payload = cbor_typeof<cbor_data>(item, cbor_type_t::cbor_type_data);
                if (nullptr == cbor_payload) {
                    ret = errorcode_t::bad_data;
                    break;
                }

                variant_binary(cbor_payload->data(), handle->payload);
            } else if (cose_message_type_tag == typeof_item) {
                cbor_data* cbor_item = cbor_typeof<cbor_data>(item, cbor_type_t::cbor_type_data);
                if (nullptr == cbor_item) {
                    ret = errorcode_t::bad_data;
                    break;
                }

                variant_binary(cbor_item->data(), handle->tag);
            } else if (cose_message_type_signature == typeof_item) {
                cbor_data* cbor_item = cbor_typeof<cbor_data>(item, cbor_type_t::cbor_type_data);
                if (nullptr == cbor_item) {
                    ret = errorcode_t::bad_data;
                    break;
                }

                cose_parts_t part;
                variant_binary(cbor_item->data(), part.bin_data);
                handle->subitems.push_back(part);
            } else if (cose_message_type_items == typeof_item) {
                cbor_array* cbor_items = cbor_typeof<cbor_array>(item, cbor_type_t::cbor_type_array);
                if (nullptr == cbor_items) {
                    ret = errorcode_t::bad_data;
                    break;
                }

                size_t size_array = cbor_items->size();
                for (size_t i = 0; i < size_array; i++) {
                    cbor_array* cbor_item = (cbor_array*)(*cbor_items)[i];  // signature, recipient
                    if (3 == cbor_item->size()) {
                        cbor_data* cbor_signer_protected = cbor_typeof<cbor_data>((*cbor_item)[0], cbor_type_t::cbor_type_data);
                        cbor_map* cbor_signer_unprotected = cbor_typeof<cbor_map>((*cbor_item)[1], cbor_type_t::cbor_type_map);
                        cbor_data* cbor_signer_signature = cbor_typeof<cbor_data>((*cbor_item)[2], cbor_type_t::cbor_type_data);

                        cose_parts_t part;
                        variant_binary(cbor_signer_protected->data(), part.bin_protected);
                        variant_binary(cbor_signer_signature->data(), part.bin_data);
                        composer.parse_binary(part.bin_protected, part.protected_map);
                        composer.parse_unprotected(cbor_signer_unprotected, part);
                        handle->subitems.push_back(part);
                    }
                }
            }
        }
    }
    __finally2 {
        reader.close(reader_context);

        if (root) {
            root->release();
        }
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::parse_binary(binary_t const& data, cose_variantmap_t& vtl) {
    return_t ret = errorcode_t::success;
    cbor_reader reader;
    cbor_reader_context_t* reader_context = nullptr;
    cbor_object* root = nullptr;

    __try2 {
        ret = reader.open(&reader_context);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = reader.parse(reader_context, data);
        if (errorcode_t::success != ret) {
            __leave2;  // bstr of length zero is used
        }
        ret = reader.publish(reader_context, &root);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (nullptr == root) {
        }

        if (cbor_type_t::cbor_type_map != root->type()) {
            ret = errorcode_t::bad_data;
            __leave2_trace(ret);
        }

        ret = parse_map((cbor_map*)root, vtl);
    }
    __finally2 {
        reader.close(reader_context);

        if (root) {
            root->release();
        }
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::parse_map(cbor_map* root, cose_variantmap_t& vtl) {
    return_t ret = errorcode_t::success;

    __try2 {
        size_t size_map = root->size();
        for (size_t i = 0; i < size_map; i++) {
            cbor_pair* pair = (*root)[i];
            cbor_data* pair_key = (cbor_data*)pair->left();
            cbor_object* pair_value = (cbor_object*)pair->right();
            cbor_type_t type_value = pair_value->type();
            int keyid = 0;
            keyid = t_variant_to_int<int>(pair_key->data());
            if (cbor_type_t::cbor_type_data == type_value) {
                cbor_data* data = (cbor_data*)pair_value;
                variant_t vt;
                variant_copy(&vt, &data->data());
                vtl.insert(std::make_pair(keyid, vt));
            }
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t cbor_object_signing_encryption::composer::parse_unprotected(cbor_map* root, cose_parts_t& part) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        size_t size_map = root->size();
        for (size_t i = 0; i < size_map; i++) {
            cbor_pair* pair = (*root)[i];
            cbor_data* pair_key = (cbor_data*)pair->left();
            cbor_object* pair_value = (cbor_object*)pair->right();
            cbor_type_t type_value = pair_value->type();
            int keyid = 0;
            cose_variantmap_t dh_key;

            keyid = t_variant_to_int<int>(pair_key->data());

            if (cbor_type_t::cbor_type_data == type_value) {
                cbor_data* data = (cbor_data*)pair_value;
                variant_t vt;
                variant_copy(&vt, &data->data());
                part.unprotected_map.insert(std::make_pair(keyid, vt));
            } else if (cbor_type_t::cbor_type_map == type_value) {
                cbor_map* map_value = (cbor_map*)pair->right();
                if (-1 == keyid || -2 == keyid) {
                    // -1 cose_ephemeral_key
                    // -2 cose_static_key

                    parse_map(map_value, dh_key);

                    return_t check = errorcode_t::success;
                    variant_t vt;
                    maphint<int, variant_t> hint(dh_key);
                    check = hint.find(cose_key_lable_t::cose_lable_kty, &vt);
                    int kty = t_variant_to_int<int>(vt);
                    if (cose_kty_t::cose_kty_ec2 == kty || cose_kty_t::cose_kty_okp == kty) {
                        int crv = 0;
                        binary_t bin_x;
                        binary_t bin_y;
                        binary_t bin_d;
                        bool ysign = true;

                        check = hint.find(cose_key_lable_t::cose_ec_crv, &vt);
                        crv = t_variant_to_int<int>(vt);
                        check = hint.find(cose_key_lable_t::cose_ec_x, &vt);
                        variant_binary(vt, bin_x);
                        check = hint.find(cose_key_lable_t::cose_ec_y, &vt);
                        if (TYPE_BOOLEAN == vt.type) {
                            ysign = vt.data.b;
                        } else {
                            variant_binary(vt, bin_y);
                        }

                        uint32 nid = advisor->curveof((cose_ec_curve_t)crv);

                        crypto_key key;
                        crypto_keychain keychain;
                        if (bin_d.size()) {
                            keychain.add_ec(&key, nullptr, nullptr, nid, bin_x, bin_y, bin_d);
                        } else {
                            keychain.add_ec(&key, nullptr, nullptr, nid, bin_x, ysign ? 1 : 0, bin_d);
                        }
                        part.epk = key.any(true);
                    }
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

bool cbor_object_signing_encryption::composer::exist(int key, cose_variantmap_t& from) {
    bool ret_value = false;
    return_t ret = errorcode_t::success;
    cose_variantmap_t::iterator iter;
    basic_stream cosekey;
    variant_t vt;

    maphint<int, variant_t> hint(from);
    ret = hint.find(key, &vt);
    if (errorcode_t::success == ret) {
        ret_value = true;
    }
    return ret_value;
}

return_t cbor_object_signing_encryption::composer::finditem(int key, int& value, cose_variantmap_t& from) {
    return_t ret = errorcode_t::success;
    cose_variantmap_t::iterator iter;
    basic_stream cosekey;
    variant_t vt;

    maphint<int, variant_t> hint(from);
    ret = hint.find(key, &vt);
    if (errorcode_t::success == ret) {
        value = t_variant_to_int<int>(vt);
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::finditem(int key, std::string& value, cose_variantmap_t& from) {
    return_t ret = errorcode_t::success;
    variant_t vt;

    maphint<int, variant_t> hint(from);
    ret = hint.find(key, &vt);
    if (errorcode_t::success == ret) {
        variant_string(vt, value);
    }
    return ret;
}

return_t cbor_object_signing_encryption::composer::finditem(int key, binary_t& value, cose_variantmap_t& from) {
    return_t ret = errorcode_t::success;
    variant_t vt;

    maphint<int, variant_t> hint(from);
    ret = hint.find(key, &vt);
    if (errorcode_t::success == ret) {
        variant_binary(vt, value);
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
