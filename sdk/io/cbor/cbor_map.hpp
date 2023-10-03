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

#ifndef __HOTPLACE_SDK_IO_CBOR_CBORMAP__
#define __HOTPLACE_SDK_IO_CBOR_CBORMAP__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/io/cbor/cbor_object.hpp>
#include <hotplace/sdk/io/stream/stream.hpp>
#include <deque>

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
class cbor_pair : public cbor_object
{
    friend class cbor_map;
    friend class cbor_concise_visitor;
    friend class cbor_diagnostic_visitor;
public:
#if defined __SIZEOF_INT128__
    cbor_pair (int128 value, cbor_data* object);
    cbor_pair (int128 value, cbor_map* object);
    cbor_pair (int128 value, cbor_array* object);
#else
    cbor_pair (int64 value, cbor_data* object);
    cbor_pair (int64 value, cbor_map* object);
    cbor_pair (int64 value, cbor_array* object);
#endif
    cbor_pair (const char* key, cbor_data* object);
    cbor_pair (const char* key, cbor_map* object);
    cbor_pair (const char* key, cbor_array* object);
    cbor_pair (cbor_data* key, cbor_data* object);
    cbor_pair (cbor_data* key, cbor_map* object);
    cbor_pair (cbor_data* key, cbor_array* object);
    virtual ~cbor_pair ();

    cbor_data* const left ();
    cbor_object* const right ();

    virtual int addref ();
    virtual int release ();

protected:
    cbor_pair (cbor_data* key, cbor_object* object);

    virtual void represent (stream_t* s);
    virtual void represent (binary_t* b);

private:
    cbor_data* _lhs;
    cbor_object* _rhs;
};

/*
 * @biref   map type
 * @example
 *          // {1:2,3:4}
 *          cbor_map* root = new cbor_map ();
 *          *root << new cbor_pair (1, new cbor_data (2)) << new cbor_pair (3, new cbor_data (4));
 *          // ...
 *          root->release ();
 */
class cbor_map : public cbor_object
{
    friend class cbor_concise_visitor;
    friend class cbor_diagnostic_visitor;
public:
    cbor_map ();
    cbor_map (uint32 flags);
    cbor_map (cbor_pair* object, uint32 flags = 0);
    virtual ~cbor_map ();

    /*
     * @brief   add
     * @param   cbor_object* object [in]
     * @param   cbor_object* extra [inopt] MUST NOT null
     * @return  error code (see error.hpp)
     */
    virtual return_t join (cbor_object* object, cbor_object* extra = nullptr);
    cbor_map& add (cbor_object* object, cbor_object* extra = nullptr);
    cbor_map& add (cbor_pair* object);
    cbor_map& operator << (cbor_pair* object);

    virtual size_t size ();
    cbor_pair const* operator [] (size_t index);
    std::list <cbor_pair*> const& accessor ();

    virtual int addref ();
    virtual int release ();

protected:

    virtual void represent (stream_t* s);
    virtual void represent (binary_t* b);

private:
    std::list <cbor_pair*> _array; /* unordered */
};

}
}  // namespace

#endif
