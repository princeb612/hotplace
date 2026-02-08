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

#ifndef __HOTPLACE_SDK_BASE_NOSTD_PRIORITYQUEUE__
#define __HOTPLACE_SDK_BASE_NOSTD_PRIORITYQUEUE__

#include <hotplace/sdk/base/nostd/vector.hpp>
#include <hotplace/sdk/base/syntax.hpp>
#include <hotplace/sdk/base/types.hpp>

namespace hotplace {

/**
 * @brief   heap
 * @refer   Data Structures and Algorithm Analysis in C++ - 6 Priority Queues (Heaps)
 */
template <typename T>
class t_binary_heap {
   public:
    explicit t_binary_heap() : _array(10), _size(0) {}
    explicit t_binary_heap(const t_binary_heap& rhs) : _array(rhs._array), _size(rhs._size) {}
    explicit t_binary_heap(const t_vector<T>& rhs) : _array(rhs.size() + 10), _size(rhs.size()) {
        for (size_t i = 0; i < rhs.size(); ++i) {
            _array[i + 1] = rhs[i];
        }
        build_heap();
    }

    bool empty() const { return 0 == _size; }
    const T& top() const {
        if (empty()) {
            throw exception(errorcode_t::empty);
        }
        return _array[1];
    }

    void push(const T& x) {
        if (_size == _array.size() - 1) {
            _array.resize(_array.size() << 1);
        }

        size_t hole = ++_size;
        T tmp = x;
        _array[0] = std::move(tmp);
        // percolate up using the temporary value instead of repeatedly reading x.
        for (; hole > 1 && _array[0] < _array[hole / 2]; hole /= 2) {
            _array[hole] = std::move(_array[hole / 2]);
        }
        _array[hole] = std::move(_array[0]);
    }
    void push(T&& x) {
        if (_size == _array.size() - 1) {
            _array.resize(_array.size() << 1);
        }

        size_t hole = ++_size;

        _array[0] = std::move(x);
        // after std::move, x is in a valid but unspecified state; always compare using the stored sentinel.
        for (; hole > 1 && _array[0] < _array[hole / 2]; hole /= 2) {
            _array[hole] = std::move(_array[hole / 2]);
        }
        _array[hole] = std::move(_array[0]);
    }
    void pop() {
        if (empty()) {
            throw exception(errorcode_t::empty);
        }
        _array[1] = std::move(_array[_size--]);
        percolate_down(1);
    }
    void pop(T& x) {
        if (empty()) {
            throw exception(errorcode_t::empty);
        }
        x = std::move(_array[1]);
        _array[1] = std::move(_array[_size--]);
        percolate_down(1);
    }
    void clear() { _size = 0; }
    size_t size() const { return _size; }

   private:
    t_vector<T> _array;
    size_t _size;

    void build_heap() {
        for (size_t i = _size / 2; i > 0; --i) {
            percolate_down(i);
        }
    }
    void percolate_down(size_t hole) {
        size_t child = 0;
        T tmp = std::move(_array[hole]);
        for (; hole * 2 <= _size; hole = child) {
            child = hole << 1;
            if ((child != _size) && (_array[child + 1] < _array[child])) {
                ++child;
            }
            if (_array[child] < tmp) {
                _array[hole] = std::move(_array[child]);
            } else {
                break;
            }
        }
        _array[hole] = std::move(tmp);
    }
};

}  // namespace hotplace

#endif
