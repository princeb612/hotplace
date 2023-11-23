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

#ifndef __HOTPLACE_SDK_IO_CBOR_CBORMAP__
#define __HOTPLACE_SDK_IO_CBOR_CBORMAP__

#include <deque>
#include <map>
#include <sdk/base.hpp>
#include <sdk/io/cbor/cbor_object.hpp>
#include <sdk/io/stream/stream.hpp>

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

/*
 * @biref   map type
 * @example
 *          // {1:2,3:4}
 *          cbor_map* root = new cbor_map ();
 *          *root << new cbor_pair (1, new cbor_data (2)) << new cbor_pair (3, new cbor_data (4));
 *          // ...
 *          root->release ();
 */
class cbor_map : public cbor_object {
    friend class cbor_concise_visitor;
    friend class cbor_diagnostic_visitor;

   public:
    cbor_map();
    cbor_map(uint32 flags);
    cbor_map(cbor_pair* object, uint32 flags = 0);
    virtual ~cbor_map();

    /*
     * @brief   add
     * @param   cbor_object* object [in]
     * @param   cbor_object* extra [inopt] MUST NOT null
     * @return  error code (see error.hpp)
     */
    virtual return_t join(cbor_object* object, cbor_object* extra = nullptr);
    cbor_map& add(cbor_object* object, cbor_object* extra = nullptr);
    cbor_map& add(cbor_pair* object);
    cbor_map& operator<<(cbor_pair* object);

    virtual size_t size();
    cbor_pair* operator[](size_t index);
    std::list<cbor_pair*>& accessor();

    virtual int addref();
    virtual int release();

   protected:
    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

   private:
    std::list<cbor_pair*> _array; /* unordered */
};

/**
 * @brief   hint
 * @remarks
 *          // sketch
 *          cbor_map_hint<int, cbor_map_int_binder<int>> hint(map);
 *          cbor_object* cbor_curve = nullptr;
 *          hint.find(cose_key_lable_t::cose_ec_crv, &cbor_curve);
 *          // ...
 *          cbor_curve->release();
 */

template <typename KTY>
struct cbor_map_int_binder {
    KTY bind(variant_t vt) { return t_variant_to_int<KTY>(vt); }
};

template <typename KTY>
struct cbor_map_string_binder {
    KTY bind(variant_t vt) {
        KTY value;
        variant_string(vt, value);
        return value;
    }
};

/**
 * @brief build index if necesary
 */
template <typename KTY, typename VTK>
class cbor_map_hint {
   public:
    cbor_map_hint(cbor_map* source) : _source(source) {
        _source->addref();
        build();
    }
    ~cbor_map_hint() { _source->release(); }

    /**
     * @brief find
     * @example
     *          cbor_map_hint<int, cbor_map_int_binder<int>> hint(map)
     *          cbor_object* item = nullptr;
     *          ret = hint.find(1, &item);
     *          if (errorcode_t::success == ret) {
     *              // ...
     *              item->release();
     *          }
     */
    return_t find(KTY key, cbor_object** item) {
        return_t ret = errorcode_t::success;
        __try2 {
            if (nullptr == item) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }

            typename std::map<KTY, cbor_object*>::iterator iter;
            iter = _index.find(key);
            if (_index.end() == iter) {
                ret = errorcode_t::not_found;
            } else {
                cbor_object* object = iter->second;
                object->addref();
                *item = object;
            }
        }
        __finally2 {
            // do nothing
        }
        return ret;
    }
    void get_order(std::list<KTY>& order) { order = _order; }

   protected:
    void build() {
        for (size_t i = 0; i < _source->size(); i++) {
            cbor_pair* pair = (*_source)[i];
            cbor_data* left = pair->left();
            cbor_object* right = pair->right();
            KTY key = _binder.bind(left->data());
            _order.push_back(key);
            _index.insert(std::make_pair(key, right));
        }
    }

   private:
    cbor_map* _source;
    std::list<KTY> _order;
    std::map<KTY, cbor_object*> _index;
    VTK _binder;
};

}  // namespace io
}  // namespace hotplace

#endif
