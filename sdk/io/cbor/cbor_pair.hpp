/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7049 Concise Binary Object Representation (CBOR)
 *  RFC 8949 Concise Binary Object Representation (CBOR)
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_IO_CBOR_CBORPAIR__
#define __HOTPLACE_SDK_IO_CBOR_CBORPAIR__

#include <sdk/io/cbor/cbor_object.hpp>

namespace hotplace {
namespace io {

/*
 * @brief   pair type
 * @desc    key (int, string) : value (int, string, array)
 *          {1: 2, 3: 4}
 *          {"a": 1, "b": [2, 3]}
 *          {"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"}
 *          {_ "a": 1, "b": [_ 2, 3]}
 *          {_ "Fun": true, "Amt": -2}
 * @sa      cbor_map
 */
class cbor_pair : public cbor_object {
    friend class cbor_map;
    friend class cbor_concise_visitor;
    friend class cbor_diagnostic_visitor;

   public:
#if defined __SIZEOF_INT128__
    cbor_pair(int128 value, cbor_data* object);
    cbor_pair(int128 value, cbor_map* object);
    cbor_pair(int128 value, cbor_array* object);
#else
    cbor_pair(int64 value, cbor_data* object);
    cbor_pair(int64 value, cbor_map* object);
    cbor_pair(int64 value, cbor_array* object);
#endif
    cbor_pair(const char* key, cbor_data* object);
    cbor_pair(const char* key, cbor_map* object);
    cbor_pair(const char* key, cbor_array* object);
    cbor_pair(cbor_data* key, cbor_data* object);
    cbor_pair(cbor_data* key, cbor_map* object);
    cbor_pair(cbor_data* key, cbor_array* object);
    virtual ~cbor_pair();

    cbor_data* left();
    cbor_object* right();

    virtual int addref();
    virtual int release();

   protected:
    cbor_pair(cbor_data* key, cbor_object* object);

    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

   private:
    cbor_data* _lhs;
    cbor_object* _rhs;
};

}  // namespace io
}  // namespace hotplace

#endif
