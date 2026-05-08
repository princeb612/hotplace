/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * graph online https://graphonline.ru/en/
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_NOSTD_GRAPH__
#define __HOTPLACE_SDK_BASE_BASIC_NOSTD_GRAPH__

#include <algorithm>
#include <list>
#include <map>
#include <queue>
#include <sdk/base/basic/nostd/container.hpp>
#include <sdk/base/stl.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <set>
#include <vector>

namespace hotplace {

/**
 * sketch
 *
 *          t_graph<int> graph;
 *          graph.add_edge(1, 2)
 *               .add_edge(1, 3)
 *               .add_edge(1, 4)
 *               .add_edge(2, 4)
 *               .add_edge(2, 5)
 *               .add_edge(3, 6)
 *               .add_edge(4, 3)
 *               .add_edge(4, 6)
 *               .add_edge(4, 7)
 *               .add_edge(5, 4)
 *               .add_edge(5, 7)
 *               .add_edge(7, 6);
 *          // set weight and direction
 *          // g.add_edge(1, 8, 1, graph_direction_t::graph_undirected);
 *          // g.add_edge(7, 8, 2, graph_direction_t::graph_undirected);
 *          auto dfs = graph.build_dfs()
 *          dfs->learn().infer();
 *          auto infer_handler = [](const int& i, const std::vector<int>& v) -> void {
 *              basic_stream bs;
 *              print<std::vector<int>, basic_stream>(v, bs, "(", ", ", ")");
 *              std::cout << bs << std::endl;
 *              fflush(stdout);
 *          };
 *          dfs->traverse(handler);
 */
enum graph_direction_t {
    graph_undirected = 0,
    graph_directed = 1,
};

template <typename T>
class t_graph {
   private:
    enum label_t {
        label_unvisited = 0,
        label_visited = 1,
    };

    struct vertex {
        T _data;

        vertex(const T& d = T()) : _data(d) {}
        vertex(T&& d) : _data(std::move(d)) {}

        vertex(const vertex& rhs) : _data(rhs._data) {}
        vertex(vertex&& rhs) : _data(std::move(rhs._data)) {}

        vertex& operator=(const vertex& rhs) {
            _data = rhs._data;
            return *this;
        }
        vertex& operator=(vertex&& rhs) {
            _data = std::move(rhs._data);
            return *this;
        }

        operator T() const { return _data; }
        operator T() { return _data; }
    };
    struct edge {
        vertex _from;
        vertex _to;
        int _weight;
        graph_direction_t _direction;

        edge(const T& from, const T& to, int weight = 1, graph_direction_t d = graph_directed) : _from(from), _to(to), _direction(d), _weight(weight) {
            adjust();
        }
        edge(T&& from, T&& to, int weight = 1, graph_direction_t d = graph_directed)
            : _from(std::move(from)), _to(std::move(to)), _weight(weight), _direction(d) {
            adjust();
        }

        edge(const vertex& from, const vertex& to, int weight = 1, graph_direction_t d = graph_directed)
            : _from(from), _to(to), _weight(weight), _direction(d) {
            adjust();
        }
        edge(vertex&& from, vertex&& to, graph_direction_t d = graph_directed, int weight = 1)
            : _from(std::move(from)), _to(std::move(to)), _weight(weight), _direction(d) {
            adjust();
        }

        edge(const edge& rhs) : _from(rhs._from), _to(rhs._to), _weight(rhs._weight), _direction(rhs._direction) {}
        edge(edge&& rhs) : _from(std::move(rhs._from)), _to(std::move(rhs._to)), _weight(rhs._weight), _direction(rhs._direction) {}

        void set_weight(int weight) { _weight = weight; }
        int get_weight() { return _weight; }
        void set_direction(graph_direction_t d) { _direction = d; }
        graph_direction_t get_direction() { return _direction; }

        void adjust() {
            if (_from == _to) {
                _weight = 0;
            }
        }
        void change_vertex() { std::swap(_from, _to); }
    };
    /**
     * @brief   tag
     * @comments
     *          std::map<edge, tag>
     *              edge::weight, direction - unchangable
     *              tag::label, distance - changable
     */
    struct tag {
        label_t _label;
        int _weight;
        int _distance;

        tag() : _label(label_unvisited), _weight(0), _distance(0) {}
        tag(const tag& rhs) : _label(rhs._label), _weight(rhs._weight), _distance(rhs._distance) {}

        void set_label(label_t tag) { _label = tag; }
        label_t get_label() { return _label; }

        void unvisit() { set_label(label_unvisited); }
        void visit() { set_label(label_visited); }

        bool is_unvisited() { return label_unvisited == get_label(); }
        bool is_visited() { return label_visited == get_label(); }
    };

    friend bool operator<(const vertex& lhs, const vertex& rhs) { return lhs._data < rhs._data; }
    friend bool operator==(const vertex& lhs, const vertex& rhs) { return lhs._data == rhs._data; }
    friend bool operator<(const edge& lhs, const edge& rhs) {
        bool ret = true;
        if (lhs._from < rhs._from) {
            // do nothing
        } else if (lhs._from == rhs._from) {
            ret = (lhs._to < rhs._to);
        } else {
            ret = false;
        }
        return ret;
    }

    typedef std::set<vertex> unordered_vertices_t;
    typedef std::set<edge> unordered_edges_t;
    typedef std::list<vertex> ordered_vertices_t;
    typedef std::list<edge> ordered_edges_t;

   public:
    t_graph() {}

    t_graph& add_vertex(const T& d) {
        vertex v(d);
        add_vertex(std::move(v));
        return *this;
    }
    t_graph& add_vertex(T&& d) {
        add_vertex(vertex(std::move(d)));
        return *this;
    }
    t_graph& add_vertex(const vertex& v) {
        std::pair<typename unordered_vertices_t::iterator, bool> pib = _unordered_vertices.insert(v);
        if (true == pib.second) {
            _ordered_vertices.push_back(v);
        }
        return *this;
    }
    t_graph& add_vertex(vertex&& v) {
        std::pair<typename unordered_vertices_t::iterator, bool> pib = _unordered_vertices.insert(std::move(v));
        if (true == pib.second) {
            _ordered_vertices.push_back(v);
        }
        return *this;
    }

    t_graph& add_edge(const T& from, const T& to, int weight = 1, graph_direction_t d = graph_directed) {
        edge e(from, to, weight, d);
        add_edge(std::move(e));
        return *this;
    }
    t_graph& add_edge(const vertex& from, const vertex& to, int weight = 1, graph_direction_t d = graph_directed) {
        edge e(from, to, weight, d);
        add_edge(std::move(e));
        return *this;
    }

    t_graph& add_directed_edge(const T& from, const T& to, int weight = 1) { return add_edge(from, to, weight, graph_direction_t::graph_directed); }
    t_graph& add_directed_edge(const vertex& from, const vertex& to, int weight = 1) { return add_edge(from, to, weight, graph_direction_t::graph_directed); }
    t_graph& add_undirected_edge(const T& from, const T& to, int weight = 1) { return add_edge(from, to, weight, graph_direction_t::graph_undirected); }
    t_graph& add_undirected_edge(const vertex& from, const vertex& to, int weight = 1) {
        return add_edge(from, to, weight, graph_direction_t::graph_undirected);
    }

    t_graph& add_edge(const edge& e) {
        __try2 {
            if (graph_undirected == e._direction) {
                edge r(e._to, e._from);
                auto item = _unordered_edges.find(std::move(r));
                if (_unordered_edges.end() != item) {
                    __leave2;
                }
            }
            std::pair<typename unordered_edges_t::iterator, bool> pib = _unordered_edges.insert(e);
            if (pib.second) {
                add_vertex(e._from).add_vertex(e._to);

                _ordered_edges.push_back(e);

#if 1
                if (graph_undirected == e._direction) {
                    _unordered_edges.insert(edge(e._to, e._from, e._weight, e._direction));
                }
#endif
            }
        }
        __finally2 {
            // do nothing
        }
        return *this;
    }
    t_graph& add_edge(edge&& e) {
        edge temp(std::move(e));
        return add_edge(temp);
    }

    const unordered_vertices_t& get_unordered_vertices() const { return _unordered_vertices; }
    const unordered_edges_t& get_unordered_edges() const { return _unordered_edges; }
    const ordered_vertices_t& get_ordered_vertices() const { return _ordered_vertices; }
    const ordered_edges_t& get_ordered_edges() const { return _ordered_edges; }

   private:
    unordered_vertices_t _unordered_vertices;
    unordered_edges_t _unordered_edges;
    ordered_vertices_t _ordered_vertices;
    ordered_edges_t _ordered_edges;

   public:
    class graph_search {
       protected:
        typedef std::list<T> result_t;
        typedef std::map<T, result_t> results_map_t;
        typedef std::set<T> neighbour_t;

       public:
        typedef std::function<void(const T&, const std::list<T>&)> visitor_t;

        graph_search(const t_graph<T>& g) : _g(g) {}

        virtual graph_search& learn() {
            do_learn();
            return *this;
        }

        virtual graph_search& infer() {
            _results.clear();
            for (auto n : _neighbours) {
                unvisit();
                do_infer(n.first);
            }
            return *this;
        }

        virtual void traverse(visitor_t f) {
            for (auto n : _neighbours) {
                do_traverse(n.first, f);
            }
        }
        virtual void traverse(const T& u, visitor_t f) { do_traverse(u, f); }

       protected:
        virtual void do_learn() {
            for (auto item : _g._unordered_vertices) {
                _visit.insert({item, false});
                neighbour_t n;
                _neighbours.insert({item, std::move(n)});
            }
            for (auto item : _g._unordered_edges) {
                _neighbours[item._from].insert(item._to);

                if (graph_undirected == item._direction) {
                    _neighbours[item._to].insert(item._from);
                }
            }
        }
        virtual void do_infer(const T& u) {}
        virtual void do_traverse(const T& u, visitor_t f) { f(u, _results[u]); }

        void unvisit() {
            for (auto& item : _visit) {
                item.second = false;
            }
        }
        bool visit(const T& t) {
            bool ret = false;
            if (false == _visit[t]) {
                _visit[t] = true;
                ret = true;
            }
            return ret;
        }
        bool visit(const T& t, std::set<edge>& connected) {
            bool ret = false;
            auto& neighbour = _neighbours.find(t)->second;
            for (auto item : neighbour) {  // for each adjacent vertex
                auto iter = _unordered_edges.find(edge(t, item));
                if (_unordered_edges.end() != iter) {
                    connected.insert(*iter);
                } else {
                    iter = _unordered_edges.find(edge(item, t));
                    if (_unordered_edges.end() != iter) {
                        if (graph_undirected == iter->_direction) {
                            connected.insert(*iter);  // undirected edge
                        }
                    }
                }
            }
            return ret;
        }
        int get_weight(const T& from, const T& to) {
            int weight = -1;
            if (from == to) {
                weight = 0;
            } else {
                auto& edges = _g._unordered_edges;
                auto item = edges.find(edge(from, to));
                if (edges.end() != item) {
                    weight = item->_weight;
                }
            }
            return weight;
        }

        const t_graph<T>& _g;

        std::map<T, neighbour_t> _neighbours;
        std::map<T, bool> _visit;

        results_map_t _results;
    };

    class graph_adjacent_list : public graph_search {
       public:
        graph_adjacent_list(const t_graph<T>& g) : graph_search(g) {}

       protected:
        virtual void do_infer(const T& u) {
            auto& result = this->_results[u];
            auto& neighbours = this->_neighbours;
            auto& neighbour = neighbours.find(u)->second;
            for (auto n : neighbour) {
                result.push_back(n);
            }
        }

       private:
    };

    /*
     * @brief   depth first search
     * @refer
     *          DFS(G, u)
     *              u.visited = true
     *              for each v ∈ G.Adj[u]
     *                  if v.visited == false
     *                      DFS(G,v)
     *
     *          init() {
     *              For each u ∈ G
     *                  u.visited = false
     *               For each u ∈ G
     *                 DFS(G, u)
     *          }
     */
    class graph_dfs : public graph_search {
       public:
        typedef typename graph_search::result_t result_t;

        graph_dfs(const t_graph<T>& g) : graph_search(g) {}

       protected:
        virtual void do_infer(const T& u) {
            auto& result = this->_results[u];
            infer_recursive(u, u, result);
        }
        void infer_recursive(const T& v, const T& u, result_t& result) {
            auto& neighbours = this->_neighbours;
            auto& neighbour = neighbours.find(u)->second;
            this->visit(u);

            for (auto n : neighbour) {
                if (this->visit(n)) {
                    result.push_back(n);
                    infer_recursive(v, n, result);
                }
            }
        }

       private:
    };

    /*
     * @brief   breadth first search
     * @refer
     *          create a queue Q
     *          mark v as visited and put v into Q
     *          while Q is non-empty
     *              remove the head u of Q
     *              mark and enqueue all (unvisited) neighbours of u
     */
    class graph_bfs : public graph_search {
       public:
        graph_bfs(const t_graph<T>& g) : graph_search(g) {}

       protected:
        virtual void do_infer(const T& u) {
            auto& result = this->_results[u];
            auto& neighbours = this->_neighbours;

            this->visit(u);

            std::list<T> q;
            q.push_front(u);

            while (false == q.empty()) {
                T v = q.front();
                q.pop_front();  // remove the head

                // mark and enqueue all (unvisited) neighbours
                auto& neighbour = neighbours.find(v)->second;
                for (auto n : neighbour) {
                    if (this->visit(n)) {
                        result.push_back(n);
                        q.push_back(n);
                    }
                }
            }
        }

       private:
    };

    /*
     * @brief   shortest path
     */
    class graph_path : public graph_search {
       public:
        graph_path(const t_graph<T>& g) : graph_search(g) {}

       protected:
        virtual void do_infer(const T& u) {
            auto& result = this->_results[u];
            auto& neighbours = this->_neighbours;
            typedef std::pair<int, T> pair_t;
            std::priority_queue<pair_t, std::vector<pair_t>, std::greater<pair_t>> pq;
            std::map<T, int> dist;
            for (auto& temp : this->_g._unordered_vertices) {
                dist[temp] = 0x1f1f;
            }
            
            this->visit(u);

            //std::list<T> q;
            // q.push_front(u);
            pq.push({0, u});
            dist[u] = 0;

            while (false == pq.empty()) {
                // T v = q.front();
                // q.pop_front();  // remove the head
                T v = pq.top().second;
                pq.pop();

                // mark and enqueue all (unvisited) neighbours
                auto& neighbour = neighbours.find(v)->second;
                for (auto n : neighbour) {
                    //int weight = this->_g._unordered_edges.find(edge(v, n))->_weight;
                    int weight = this->get_weight(v, n);
                    //int distn = dist[n];
                    //int distv = dist[v];
                    //if (distn > distv + weight) {
                    if (dist[n] > dist[v] + weight) {
                        dist[n] = dist[v] + weight;
                        pq.push({dist[n], n});
                    }
                    //if (this->visit(n)) {
                    //    q.push_back(n);
                    //}
                }
            }
            basic_stream bs;
            print_pair<std::map<T, int>, basic_stream>(dist, bs, "[", ", ", "]");
            std::cout << u << " -> " << bs << std::endl;
        }

       private:
    };

    graph_adjacent_list* build_adjacent() { return new graph_adjacent_list(*this); }
    graph_dfs* build_dfs() { return new graph_dfs(*this); }
    graph_bfs* build_bfs() { return new graph_bfs(*this); }
    graph_path* build_path() { return new graph_path(*this); }
};

}  // namespace hotplace

#endif
