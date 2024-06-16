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

#ifndef __HOTPLACE_SDK_BASE_NOSTD_LIST__
#define __HOTPLACE_SDK_BASE_NOSTD_LIST__

#include <sdk/base/nostd/exception.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

/**
 * @brief   list
 * @refer   Data Structures and Algorithm Analysis in C++ - 3 Lists, Stacks, and Queues
 */
template <typename T>
class t_list {
   private:
    struct node {
        T _data;
        node* _prev;
        node* _next;

        node(const T& d = T(), node* prev = nullptr, node* next = nullptr) : _data(d), _prev(prev), _next(next) {}
        node(T&& d, node* prev = nullptr, node* next = nullptr) : _data(std::move(d)), _prev(prev), _next(next) {}
    };

   public:
    class const_iterator {
       public:
        const_iterator(const t_list<T>& l, node* p) : _list(&l), _current(p) {}

        const T& operator*() const { return retrieve(); }
        const_iterator& operator++() {
            _current = _current->_next;
            return *this;
        }
        const_iterator operator++(int) {
            const_iterator old = *this;
            ++(*this);
            return old;
        }
        const_iterator& operator--() {
            _current = _current->_prev;
            return *this;
        }
        const_iterator operator--(int) {
            const_iterator old = *this;
            --(*this);
            return old;
        }
        bool operator==(const const_iterator& rhs) const { return _current == rhs._current; }
        bool operator!=(const const_iterator& rhs) const { return (false == (*this == rhs)); }

        void isvalid() const {
            if (nullptr == _list || nullptr == _current || _current == _list->_head) {
                throw exception(errorcode_t::bad_data);
            }
        }

       protected:
        const t_list<T>* _list;
        node* _current;
        T& retrieve() const { return _current->_data; }
        const_iterator(node* p) : _current(p) {}
        friend class t_list<T>;
    };
    class iterator : public const_iterator {
       public:
        iterator(const t_list<T>& l, node* p) : const_iterator(l, p) {}

        T& operator*() { return const_iterator::retrieve(); }
        const T& operator*() const { return const_iterator::operator*(); }

        iterator& operator++() {
            this->_current = this->_current->_next;
            return *this;
        }
        iterator operator++(int) {
            iterator old = *this;
            ++(*this);
            return old;
        }
        iterator& operator--() {
            this->_current = this->_current->_prev;
            return *this;
        }
        iterator operator--(int) {
            iterator old = *this;
            --(*this);
            return old;
        }

       protected:
        iterator(node* p) : const_iterator{p} {}
        friend class t_list<T>;
    };

    T& front() { return *begin(); }
    const T& front() const { return *begin(); }
    T& back() { return *--end(); }
    const T& back() const { return *--end(); }
    void push_front(const T& x) { insert(begin(), x); }
    void push_front(T&& x) { insert(begin(), std::move(x)); }
    void push_back(const T& x) { insert(end(), x); }
    void push_back(T&& x) { insert(end(), std::move(x)); }
    void pop_front() { erase(begin()); }
    void pop_back() { erase(--end()); }

    iterator insert(iterator iter, const T& x) {
        iter.isvalid();
        if (iter._list != this) {
            throw exception(errorcode_t::mismatch);
        }
        node* p = iter._current;
        _size++;
        return iterator(*this, p->_prev = p->_prev->_next = new node(x, p->_prev, p));
    }
    iterator insert(iterator iter, T&& x) {
        node* p = iter._current;
        _size++;
        return p->_prev = p->_prev->_next = new node(std::move(x), p->_prev, p);
    }
    iterator erase(iterator iter) {
        node* p = iter._current;
        iterator ret{p->_next};
        p->_prev->_next = p->_next;
        p->_next->_prev = p->_prev;
        delete p;
        _size--;
        return ret;
    }
    iterator erase(iterator from, iterator to) {
        for (iterator iter = from; iter != to;) {
            iter = erase(iter);
        }
        return to;
    }

   public:
    t_list() { init(); }
    t_list(const t_list& rhs) {
        init();
        for (auto& x : rhs) {
            push_back(x);
        }
    }
    t_list(t_list&& rhs) : _size(rhs._size), _head(rhs._head), _tail(rhs._tail) { rhs.init(); }
    ~t_list() {
        clear();
        delete _head;
        delete _tail;
    }

    t_list& operator=(const t_list& rhs) {
        t_list temp = rhs;
        std::swap(*this, temp);
        return *this;
    }
    t_list& operator=(t_list&& rhs) {
        clear();
        std::swap(_size, rhs._size);
        std::swap(_head, rhs._head);
        std::swap(_tail, rhs._tail);
        return *this;
    }

    iterator begin() {
        iterator iter(*this, _head);
        return ++iter;
    }
    const_iterator begin() const {
        const_iterator iter(*this, _head);
        return ++iter;
    }
    iterator end() { return iterator(*this, _tail); }
    const_iterator end() const { return const_iterator(*this, _tail); }

    int size() const { return _size; }
    bool empty() const { return 0 == size(); }
    void clear() {
        while (false == empty()) {
            pop_front();
        }
    }

   private:
    size_t _size;
    node* _head;
    node* _tail;

    void init() {
        _size = 0;
        _head = new node;
        _tail = new node;
        _head->_next = _tail;
        _tail->_prev = _head;
    }
};

/*
 * @brief   simple util
 */
template <typename single_linked_node_t>
class t_single_linkable {
   public:
    t_single_linkable() : _head(nullptr), _last(nullptr) {}

    bool add(single_linked_node_t* item) {
        bool ret = true;
        if (item) {
            item->set_next(nullptr);
            if (nullptr == _head) {
                _head = item;
            }
            if (_last) {
                _last->set_next(item);
            }
            _last = item;
        } else {
            ret = false;
        }
        return ret;
    }
    single_linked_node_t* get_head() { return _head; }

   private:
    single_linked_node_t* _head;
    single_linked_node_t* _last;
};

}  // namespace hotplace

#endif
