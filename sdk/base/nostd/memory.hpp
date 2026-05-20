/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   memory.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_MEMORY__
#define __HOTPLACE_SDK_BASE_NOSTD_MEMORY__

#include <functional>
#include <hotplace/sdk/base/basic/types.hpp>
#include <memory>

namespace hotplace {

namespace custom {

/*
 * @brief   default deleter
 */
template <typename T, typename... Args>
typename std::enable_if<!std::is_array<T>::value, std::unique_ptr<T>>::type make_unique(Args&&... args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
/**
 * @brief   T[], default deleter
 */
template <typename T>
typename std::enable_if<std::is_array<T>::value, std::unique_ptr<T>>::type make_unique(size_t size) {
    typedef typename std::remove_extent<T>::type element_type;
    return std::unique_ptr<T>(new element_type[size]());
}
/**
 * @brief   custom deleter
 * @example
 *          auto deleter = [](cbor_array* p) { p->release(); };
 *          auto root = make_unique_with_deleter<cbor_array>(deleter);
 */
template <typename T, typename D, typename... Args>
typename std::enable_if<!std::is_array<T>::value, std::unique_ptr<T, typename std::decay<D>::type>>::type make_unique_with_deleter(D&& deleter, Args&&... args) {
    typedef typename std::decay<D>::type deleter_type;
    return std::unique_ptr<T, deleter_type>(new T(std::forward<Args>(args)...), std::forward<D>(deleter));
}
/**
 * @brief   T[], custom deleter
 * @example
 *          auto deleter = [](byte_t* p) { delete[] p; };
 *          auto buffer = make_unique_with_deleter<byte_t[]>(size_buffer, deleter);
 */
template <typename T, typename D>
typename std::enable_if<std::is_array<T>::value, std::unique_ptr<T, typename std::decay<D>::type>>::type make_unique_with_deleter(size_t size, D&& deleter) {
    typedef typename std::decay<D>::type deleter_type;
    typedef typename std::remove_extent<T>::type element_type;
    return std::unique_ptr<T, deleter_type>(new element_type[size](), std::forward<D>(deleter));
}

/**
 * @brief   adopt/import and delete
 * @example
 *          // load(&protocol);
 *          auto lambda_deleter = [](network_protocol* object) -> void { object->release(); };
 *          auto protocol_ptr = make_promise_on_destruction<network_protocol*>(protocol, lambda_deleter);
 */
template <typename T, typename D>
std::unique_ptr<T, typename std::decay<D>::type> make_promise_on_destruction(T* ptr, D&& deleter) {
    typedef typename std::decay<D>::type deleter_type;

    return std::unique_ptr<T, deleter_type>(ptr, std::forward<D>(deleter));
}

}  // namespace custom

/**
 * @remarks
 *          understanding object << new A << new B << new C;
 *            - operator << (operator << (new A, new B), new C);
 *            - if an exception occurs in B, a memory leak occurs in A.
 *
 *          #1 make_unique
 *              try {
 *                  pl << std::unique_ptr<payload_member>(uint16(0), true, constexpr_extension_type)
 *                     << std::unique_ptr<payload_member>(uint16(0), true, constexpr_ext_len);
 *              } catch (...) {
 *                  throw exception(out_of_memory);
 *              }
 *              // if B fail, unique_ptr release A
 *
 *              payload& payload::operator<<(std::unique_ptr<payload_member> member) {
 *                  if (member) {
 *                      auto item = member.get();
 *                      // insert(item), push_back(item), ...
 *                      member.release();
 *                  }
 *                  return *this;
 *              }
 *
 *          #2 proxy
 *              try {
 *                  pl << new payload_member(uint16(0), true, constexpr_extension_type)
 *                     << new payload_member(uint16(0), true, constexpr_ext_len);
 *              } catch (...) {
 *                  throw exception(out_of_memory);
 *              }
 *              // if B fail, proxy release A
 *
 *              payload& payload::operator<<(t_pointer_proxy<payload_member> proxy) {
 *                  auto item = proxy.ptr;
 *                  if (item) {
 *                      // insert(item), push_back(item), ...
 *                      proxy.ptr = nullptr;
 *                  }
 *              }
 */
template <typename T>
struct t_pointer_proxy {
    T* ptr;
    std::function<void(T*)> deleter;

    t_pointer_proxy(T* p) : ptr(p) {
        deleter = [](T* p) -> void {
            if (p) {
                delete p;
            }
        };
    }
    ~t_pointer_proxy() { deleter(ptr); }

    T* get() { return ptr; }
    void set(std::function<void(T*)> func) { deleter = func; }
    void release() { ptr = nullptr; }
};

}  // namespace hotplace

#endif
