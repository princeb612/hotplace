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
    };
    struct edge {
        vertex _from;
        vertex _to;
        int _weight;
        graph_direction_t _direction;

        edge(const T& from, const T& to, int weight = 0, graph_direction_t d = graph_directed) : _from(from), _to(to), _direction(d), _weight(weight) {}
        edge(T&& from, T&& to, int weight = 0, graph_direction_t d = graph_directed)
            : _from(std::move(from)), _to(std::move(to)), _weight(weight), _direction(d) {}

        edge(const vertex& from, const vertex& to, int weight = 0, graph_direction_t d = graph_directed)
            : _from(from), _to(to), _weight(weight), _direction(d) {}
        edge(vertex&& from, vertex&& to, graph_direction_t d = graph_directed, int weight = 0)
            : _from(std::move(from)), _to(std::move(to)), _weight(weight), _direction(d) {}

        edge(const edge& rhs) : _from(rhs._from), _to(rhs._to), _weight(rhs._weight), _direction(rhs._direction) {}
        edge(edge&& rhs) : _from(std::move(rhs._from)), _to(std::move(rhs._to)), _weight(rhs._weight), _direction(rhs._direction) {}

        void set_weight(int weight) { _weight = weight; }
        int get_weight() { return _weight; }
        void set_direction(graph_direction_t d) { _direction = d; }
        graph_direction_t get_direction() { return _direction; }
    };
    /**
     * @brief   tag
     * @comments
     *          weight, direction - unchangable
     *          label, distance - changable
     */
    struct tag {
        label_t _label;
        int _distance;

        tag() : _label(label_unvisited), _distance(-1) {}
        tag(const tag& rhs) : _label(rhs._label), _distance(rhs._distance) {}

        void set_label(label_t tag) { _label = tag; }
        label_t get_label() { return _label; }

        void unvisit() { set_label(label_unvisited); }
        void visit() { set_label(label_visited); }

        bool is_unvisited() { return label_unvisited == get_label(); }
        bool is_visited() { return label_visited == get_label(); }

        void set_distance(int distance) { _distance = distance; }
        int get_distance() { return _distance; }
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
    typedef std::map<vertex, ordered_vertices_t> adjacent_t;
    typedef std::map<vertex, tag> vertices_tags_t;

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

    t_graph& add_edge(const T& from, const T& to, int weight = 0, graph_direction_t d = graph_directed) {
        edge e(from, to, weight, d);
        add_edge(std::move(e));
        return *this;
    }
    t_graph& add_edge(const vertex& from, const vertex& to, int weight = 0, graph_direction_t d = graph_directed) {
        edge e(from, to, weight, d);
        add_edge(std::move(e));
        return *this;
    }

    t_graph& add_directed_edge(const T& from, const T& to, int weight = 0) { return add_edge(from, to, weight, graph_direction_t::graph_directed); }
    t_graph& add_directed_edge(const vertex& from, const vertex& to, int weight = 0) { return add_edge(from, to, weight, graph_direction_t::graph_directed); }
    t_graph& add_undirected_edge(const T& from, const T& to, int weight = 0) { return add_edge(from, to, weight, graph_direction_t::graph_undirected); }
    t_graph& add_undirected_edge(const vertex& from, const vertex& to, int weight = 0) {
        return add_edge(from, to, weight, graph_direction_t::graph_undirected);
    }

    t_graph& add_edge(const edge& e) {
        std::pair<typename unordered_edges_t::iterator, bool> pib = _unordered_edges.insert(e);
        if (pib.second) {
            add_vertex(e._from).add_vertex(e._to);

            _ordered_edges.push_back(e);
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
       public:
        typedef std::vector<T> result_t;
        typedef std::map<T, result_t> results_map_t;
        typedef std::function<void(const T&, const std::vector<T>&)> visitor_t;

        graph_search(const t_graph<T>& g) : _g(g) {}

        virtual graph_search& learn() {
            build_tags();
            build_adjacent_list(_adjacent);

            do_learn();
            return *this;
        }

        virtual graph_search& infer() {
            _results.clear();
            for (auto v : _vertices_tags) {
                do_infer(v.first._data);
            }
            return *this;
        }
        virtual graph_search& infer(const T& u) {
            _results.clear();
            do_infer(u);
            return *this;
        }

        virtual void traverse(visitor_t f) {
            for (auto v : _vertices_tags) {
                do_traverse(v.first._data, f);
            }
        }
        virtual void traverse(const T& u, visitor_t f) { do_traverse(u, f); }

        bool touch_tag(std::function<bool(tag&)> f) {
            for (auto& item : _vertices_tags) {
                f(item.second);
            }
            return true;
        }
        bool touch_tag(const vertex& u, std::function<bool(tag&)> f) {
            bool ret = false;
            typename vertices_tags_t::iterator iter = _vertices_tags.find(u);
            if (_vertices_tags.end() != iter) {
                ret = f(iter->second);
            }
            return ret;
        }

       protected:
        virtual void do_learn() {}
        virtual void do_infer(const T& u) {}
        virtual void do_traverse(const T& u, visitor_t f) { f(u, _results[u]); }

        graph_search& build_tags() {
            for (auto v : _g._ordered_vertices) {
                _vertices_tags.insert(std::make_pair(v, tag()));
            }
            return *this;
        }

        void build_adjacent_list(adjacent_t& target) {
            target.clear();
            for (auto v : _g._ordered_vertices) {
                ordered_vertices_t ovl;
                target.insert(std::make_pair(v, std::move(ovl)));
            }
            for (auto e : _g._ordered_edges) {
                target.find(e._from)->second.push_back(e._to);
                if (graph_undirected == e.get_direction()) {
                    target.find(e._to)->second.push_back(e._from);
                }
            }
        }

        void reset_visit() {
            auto handler = [](tag& t) -> bool {
                t.unvisit();
                return true;
            };
            touch_tag(handler);
        }

        bool mark_visited(const T& v) { return mark_visited(vertex(v)); }

        bool mark_visited(const vertex& v) {
            auto handler = [](tag& t) -> bool {
                bool ret = false;
                if (t.is_unvisited()) {
                    t.visit();
                    ret = true;
                }
                return ret;
            };
            return touch_tag(v, handler);
        };

        const t_graph<T>& _g;
        vertices_tags_t _vertices_tags;  // visited, unvisited
        adjacent_t _adjacent;
        results_map_t _results;
    };

    class graph_adjacent_list : public graph_search {
       public:
        typedef typename graph_search::visitor_t visitor_t;

        graph_adjacent_list(const t_graph<T>& g) : graph_search(g) {}

       protected:
        virtual void do_infer(const T& u) {
            auto it = this->_adjacent.find(u);
            if (this->_adjacent.end() != it) {
                auto& result = this->_results[u];
                result.insert(result.end(), u);
                for (auto lit : it->second) {
                    result.insert(result.end(), lit._data);
                }
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
        typedef typename graph_search::visitor_t visitor_t;

        graph_dfs(const t_graph<T>& g) : graph_search(g) {}

       protected:
        virtual void do_infer(const T& u) {
            this->reset_visit();
            result_t& result = this->_results[u];
            result.insert(result.end(), u);
            infer_recursive(u, result);
        }
        void infer_recursive(const T& u, result_t& result) {
            this->mark_visited(u);

            auto& l = this->_adjacent.find(u)->second;
            for (auto opposite : l) {
                if (this->mark_visited(opposite)) {
                    const T& o = opposite._data;
                    result.insert(result.end(), o);
                    infer_recursive(o, result);
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
        typedef typename graph_search::visitor_t visitor_t;

        graph_bfs(const t_graph<T>& g) : graph_search(g) {}

       protected:
        virtual void do_infer(const T& u) {
            this->reset_visit();
            std::list<T> _queue;
            _queue.push_front(u);

            this->mark_visited(u);
            auto& result = this->_results[u];
            result.insert(result.end(), u);

            while (_queue.size()) {
                T v = _queue.front();
                _queue.pop_front();  // remove the head

                // mark and enqueue all (unvisited) neighbours
                auto& l = this->_adjacent.find(v)->second;
                for (auto opposite : l) {
                    if (this->mark_visited(opposite)) {
                        const T& o = opposite._data;
                        result.insert(result.end(), o);
                        _queue.push_back(o);
                    }
                }
            }
        }

       private:
    };

    /*
     * @brief   Dijkstra
     *          dijkstra(G, S)
     *              for each vertex V in G
     *                  distance[V] <- infinite
     *                  previous[V] <- NULL
     *                  If V != S, add V to Priority Queue Q
     *              distance[S] <- 0
     *
     *              while Q IS NOT EMPTY
     *                  U <- Extract MIN from Q
     *                  for each unvisited neighbour V of U
     *                      tempDistance <- distance[U] + edge_weight(U, V)
     *                      if tempDistance < distance[V]
     *                          distance[V] <- tempDistance
     *                          previous[V] <- U
     *              return distance[], previous[]
     */
    class graph_dijkstra : public graph_search {
       public:
        typedef typename graph_search::visitor_t visitor_t;

        graph_dijkstra(const t_graph<T>& g) : graph_search(g) {}

       protected:
        virtual void do_infer(const T& u) {
            this->reset_visit();
            //
        }

       private:
    };

    graph_adjacent_list* build_adjacent() { return new graph_adjacent_list(*this); }
    graph_dfs* build_dfs() { return new graph_dfs(*this); }
    graph_bfs* build_bfs() { return new graph_bfs(*this); }
    graph_dijkstra* build_dijkstra() { return new graph_dijkstra(*this); }
};

}  // namespace hotplace

#endif
