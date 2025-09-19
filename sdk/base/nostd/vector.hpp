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

#ifndef __HOTPLACE_SDK_BASE_NOSTD_VECTOR__
#define __HOTPLACE_SDK_BASE_NOSTD_VECTOR__

#include <hotplace/sdk/base/syntax.hpp>
#include <hotplace/sdk/base/types.hpp>

namespace hotplace {

/**
 * @brief   vector
 * @refer   Data Structures and Algorithm Analysis in C++ - 3 Lists, Stacks, and Queues
 */
template <typename T>
class t_vector {
   public:
    explicit t_vector(size_t size = 0) : _size(size), _capacity(size + const_vector_spare) { _items = new T[_capacity]; }
    t_vector(const t_vector& rhs) : _size(rhs._size), _capacity(rhs._capacity), _items(nullptr) {
        _items = new T[_capacity];
        for (size_t i = 0; i < _size; i++) {
            _items[i] = rhs._items[i];
        }
    }
    t_vector(t_vector&& rhs) : _size(rhs._size), _capacity(rhs._capacity), _items(rhs._items) {
        rhs._items = nullptr;
        rhs.clear();
    }
    ~t_vector() { clear(); }

    t_vector& operator=(const t_vector& rhs) {
        t_vector o = rhs;
        std::swap(*this, o);
        return *this;
    }
    t_vector& operator=(t_vector&& rhs) {
        clear();
        _size = rhs._size;
        _capacity = rhs._capacity;
        _items = rhs._items;
        rhs._items = nullptr;
        rhs._size = 0;
        rhs._capacity = 0;
        return *this;
    }
    void resize(size_t size) {
        if (size > _capacity) {
            reserve(size << 1);
        }
        _size = size;
    }
    void reserve(size_t capacity) {
        if (capacity >= _size) {
            T* items = new T[capacity];
            for (size_t i = 0; i < _size; ++i) {
                items[i] = std::move(_items[i]);
            }
            _capacity = capacity;
            std::swap(items, _items);
            delete[] items;
        }
    }
    T& operator[](size_t index) { return _items[index]; }
    const T& operator[](size_t index) const { return _items[index]; }
    bool empty() const { return 0 == size(); }
    size_t size() const { return _size; }
    int capacity() const { return _capacity; }

    void push_back(const T& x) {
        if (_size == _capacity) {
            reserve((_capacity << 1) + 1);
        }
        _items[_size++] = x;
    }
    void push_back(T&& x) {
        if (_size == _capacity) {
            reserve((_capacity << 1) + 1);
        }
        _items[_size++] = std::move(x);
    }
    void pop_back() { --_size; }
    const T& back() const { return _items[_size - 1]; }

    void clear() {
        if (_items) {
            delete[] _items;
            _items = nullptr;
        }
        _size = 0;
        _capacity = 0;
    }

    typedef T* iterator;
    typedef const T* const_iterator;

    T* begin() { return &_items[0]; }
    T* end() { return &_items[size()]; }
    const T* begin() const { return &_items[0]; }
    const T* end() const { return &_items[size()]; }

   private:
    size_t _size;
    size_t _capacity;
    T* _items;

    static const size_t const_vector_spare = 16;
};

}  // namespace hotplace

#endif
