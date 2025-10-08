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

#ifndef __HOTPLACE_SDK_IO_CBOR_CBORARRAY__
#define __HOTPLACE_SDK_IO_CBOR_CBORARRAY__

#include <hotplace/sdk/io/cbor/cbor_object.hpp>

namespace hotplace {
namespace io {

/*
 * @brief   array type
 * @example
 *          cbor_array* array = new cbor_array ();
 *          *array  << (new cbor_pair ("item1", new cbor_data ("value1")))
 *                  << (new cbor_pair ("item2", new cbor_data (12345)))
 *                  << (new cbor_pair ("item3", new cbor_data (true)))
 *                  << (new cbor_pair ("item4", new cbor_data (1.2345)))
 *                  << (new cbor_pair ("item5", new cbor_pair ("subitem1", new cbor_data ("subvalue1"))))
 *                  << (new cbor_pair ("item6", new cbor_data (true)))
 *                  << (new cbor_pair ("item7", new cbor_data ()));
 *          // ...
 *          array->release ();
 */
class cbor_array : public cbor_object {
    friend class cbor_concise_visitor;
    friend class cbor_diagnostic_visitor;

   public:
    cbor_array();
    cbor_array(uint32 flags);
    virtual ~cbor_array();

    /*
     * @brief   add
     * @param   cbor_object* object [in]
     * @param   cbor_object* extra [inopt] ignored
     * @return  error code (see error.hpp)
     */
    virtual return_t join(cbor_object* object, cbor_object* extra = nullptr);

    cbor_array& add(cbor_array* object);
    cbor_array& add(cbor_data* object);
    cbor_array& add(cbor_map* object);

    /**
     * @example
     *          // ["a",{"b":"c"}]
     *          auto root = new cbor_array();
     *          (*root)  //
     *              .add(new cbor_data("a"))
     *              .add([](cbor_map* obj) -> void { *obj << new cbor_pair("b", new cbor_data("c")); });
     *          root->release();
     */

    template <typename T>
    cbor_array& add(std::function<void(T*)> f, uint32 flags = 0);

    cbor_array& add(std::function<void(cbor_array*)> f, uint32 flags = 0);
    cbor_array& add(std::function<void(cbor_map*)> f, uint32 flags = 0);

    cbor_array& operator<<(cbor_array* object);
    cbor_array& operator<<(cbor_data* object);
    cbor_array& operator<<(cbor_map* object);

    virtual size_t size();
    cbor_object* operator[](size_t index);
    std::list<cbor_object*>& accessor();

    virtual int addref();
    virtual int release();

   protected:
    virtual void represent(stream_t* s);
    virtual void represent(binary_t* b);

   private:
    std::list<cbor_object*> _array;
};

}  // namespace io
}  // namespace hotplace

#endif
