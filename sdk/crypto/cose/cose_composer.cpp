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

#include <hotplace/sdk/crypto/cose/cose_composer.hpp>

namespace hotplace {
namespace crypto {

cose_composer::cose_composer ()
{
    // do nothing
}
cose_composer::~cose_composer ()
{
    // do nothing
}

return_t cose_composer::build_protected (cbor_data** object)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_data* part_protected = nullptr;
        binary_t dummy;
        __try_new_catch (part_protected, new cbor_data (dummy), ret, __leave2);
        *object = part_protected;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cose_composer::build_protected (cbor_data** object, cose_list_t& input)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (0 == input.size ()) {
            cbor_data* part_protected = nullptr;
            binary_t dummy;
            __try_new_catch (part_protected, new cbor_data (dummy), ret, __leave2);
            *object = part_protected;
        } else {
            binary_t bin_protected;
            cbor_map* part_protected = nullptr;

            __try_new_catch (part_protected, new cbor_map (), ret, __leave2);

            cose_list_t::iterator iter;
            for (iter = input.begin (); iter != input.end (); iter++) {
                cose_item_t& item = *iter;
                *part_protected << new cbor_pair (new cbor_data (item.key), new cbor_data (item.value));
            }

            build_protected (object, part_protected);

            part_protected->release ();
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cose_composer::build_protected (cbor_data** object, cbor_map* input)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object || nullptr == input) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin_protected;
        cbor_publisher publisher;
        publisher.publish (input, &bin_protected);

        *object = new cbor_data (bin_protected);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cose_composer::build_unprotected (cbor_map** object)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_map* part_unprotected = nullptr;

        __try_new_catch (part_unprotected, new cbor_map (), ret, __leave2);

        *object = part_unprotected;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cose_composer::build_unprotected (cbor_map** object, cose_list_t& input)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cbor_map* part_unprotected = nullptr;

        __try_new_catch (part_unprotected, new cbor_map (), ret, __leave2);

        cose_list_t::iterator iter;
        for (iter = input.begin (); iter != input.end (); iter++) {
            cose_item_t& item = *iter;
            *part_unprotected << new cbor_pair (new cbor_data (item.key), new cbor_data (item.value));
        }

        *object = part_unprotected;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cose_composer::build_data (cbor_data** object, const char* payload)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object || nullptr == payload) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        __try_new_catch (*object, new cbor_data (convert (payload)), ret, __leave2);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cose_composer::build_data (cbor_data** object, const byte_t* payload, size_t size)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        __try_new_catch (*object, new cbor_data (payload, size), ret, __leave2);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cose_composer::build_data (cbor_data** object, binary_t const& payload)
{
    return build_data (object, &payload[0], payload.size ());
}

return_t cose_composer::build_data_b16 (cbor_data** object, const char* str)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object || nullptr == str) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        __try_new_catch (*object, new cbor_data (base16_decode (str)), ret, __leave2);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

}
}  // namespace
