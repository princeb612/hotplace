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

#ifndef __HOTPLACE_SDK_BASE_NOSTD_GRAPH__
#define __HOTPLACE_SDK_BASE_NOSTD_GRAPH__

#include <algorithm>
#include <list>
#include <map>
#include <queue>
#include <sdk/base/nostd/template.hpp>
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
 *          auto handler = [](const int& i, const std::vector<int>& v) -> void {
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

                if (graph_undirected == e._direction) {
                    _unordered_edges.insert(edge(e._to, e._from, e._weight, e._direction));
                }
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
        typedef std::set<T> neighbour_t;

       public:
        static const int graph_infinite = 0x10000000;
        typedef std::function<void(const T&, const T&, int, const std::list<T>&)> visitor_t;  // from, to,wight, path

        graph_search(const t_graph<T>& g) : _g(g) {}

        virtual graph_search& learn() {
            do_setup();
            do_preview();
            for (auto n : _neighbours) {
                unvisit();
                do_learn(n.first);
            }
            return *this;
        }

        virtual graph_search& infer() {
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
        virtual void traverse(const T& from, const T& to, visitor_t f) { do_traverse(from, to, f); }

       protected:
        virtual void do_setup() {}
        virtual void do_preview() {
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
        virtual void do_learn(const T& u) {}
        virtual void do_infer(const T& u) {}
        virtual void do_traverse(const T& u, visitor_t f) {}
        virtual void do_traverse(const T& from, const T& to, visitor_t f) {}

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
        /*
         * @brief   adjacent edges
         */
        bool visit(const T& v, std::set<edge>& connected) {
            bool ret = false;
            auto& neighbour = _neighbours.find(v)->second;
            for (auto item : neighbour) {
                auto iter = _unordered_edges.find(edge(v, item));
                if (_unordered_edges.end() != iter) {
                    connected.insert(*iter);  // directed
                } else {
                    iter = _unordered_edges.find(edge(item, v));
                    if (_unordered_edges.end() != iter) {
                        if (graph_undirected == iter->_direction) {
                            connected.insert(*iter);  // undirected
                        }
                    }
                }
            }
            return ret;
        }
        /*
         * @brief   weight = directed(from -> to).weight, or weight = undirected(from <-> to).weight
         */
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
    };

    class graph_adjacent_list : public graph_search {
       public:
        graph_adjacent_list(const t_graph<T>& g) : graph_search(g) {}

       protected:
        typedef std::list<T> result_t;
        typedef std::map<T, result_t> results_map_t;
        typedef typename graph_search::visitor_t visitor_t;

        virtual void do_setup() { _results.clear(); }

        virtual void do_learn(const T& u) {
            auto& result = this->_results[u];
            auto& neighbours = this->_neighbours;

            for (const auto& neighbour : neighbours.find(u)->second) {
                result.push_back(neighbour);
            }
        }

        virtual void do_traverse(const T& u, visitor_t f) { f(u, u, 0, _results[u]); }

       private:
        std::map<T, result_t> _results;
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
        graph_dfs(const t_graph<T>& g) : graph_search(g) {}

       protected:
        typedef std::list<T> result_t;
        typedef std::map<T, result_t> results_map_t;
        typedef typename graph_search::visitor_t visitor_t;

        virtual void do_setup() { _results.clear(); }

        virtual void do_learn(const T& u) {
            auto& result = this->_results[u];
            result.push_back(u);
            learn_recursive(u, u, result);
        }
        void learn_recursive(const T& v, const T& u, result_t& result) {
            auto& neighbours = this->_neighbours;

            this->visit(u);

            for (const auto& neighbour : neighbours.find(u)->second) {
                if (this->visit(neighbour)) {
                    result.push_back(neighbour);
                    learn_recursive(v, neighbour, result);
                }
            }
        }

        virtual void do_traverse(const T& u, visitor_t f) { f(u, u, 0, _results[u]); }

       private:
        std::map<T, result_t> _results;
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
        typedef std::list<T> result_t;
        typedef std::map<T, result_t> results_map_t;
        typedef typename graph_search::visitor_t visitor_t;

        virtual void do_setup() { _results.clear(); }

        virtual void do_learn(const T& u) {
            auto& result = this->_results[u];
            auto& neighbours = this->_neighbours;

            this->visit(u);
            result.push_back(u);

            std::list<T> q;
            q.push_front(u);

            while (false == q.empty()) {
                T v = q.front();
                q.pop_front();  // remove the head

                // mark and enqueue all (unvisited) neighbours
                for (const auto& neighbour : neighbours.find(v)->second) {
                    if (this->visit(neighbour)) {
                        result.push_back(neighbour);
                        q.push_back(neighbour);
                    }
                }
            }
        }

        virtual void do_traverse(const T& u, visitor_t f) { f(u, u, 0, _results[u]); }

       private:
        std::map<T, result_t> _results;
    };

    /*
     * @brief   shortest path
     * @refer   https://en.wikipedia.org/wiki/Dijkstra%27s_algorithm
     *          using a priority queue
     *
     *               function Dijkstra(Graph, source):
     *                   create vertex priority queue Q
     *
     *                   dist[source] ← 0                          // Initialization
     *                   Q.add_with_priority(source, 0)            // associated priority equals dist[·]
     *
     *                   for each vertex v in Graph.Vertices:
     *                       if v ≠ source
     *                           prev[v] ← UNDEFINED               // Predecessor of v
     *                           dist[v] ← INFINITY                // Unknown distance from source to v
     *                           Q.add_with_priority(v, INFINITY)
     *
     *
     *                   while Q is not empty:                     // The main loop
     *                       u ← Q.extract_min()                   // Remove and return best vertex
     *                       for each neighbor v of u:             // Go through all v neighbors of u
     *                           alt ← dist[u] + Graph.Edges(u, v)
     *                           if alt < dist[v]:
     *                               prev[v] ← u
     *                               dist[v] ← alt
     *                               Q.decrease_priority(v, alt)
     *
     *                   return dist, prev
     */
    class graph_dijkstra : public graph_search {
       public:
        graph_dijkstra(const t_graph<T>& g) : graph_search(g) {}

       protected:
        typedef typename graph_search::visitor_t visitor_t;

        virtual void do_setup() {
            _path.clear();
            _route.clear();
        }

        virtual void do_learn(const T& u) {
            auto& neighbours = this->_neighbours;
            std::priority_queue<pair_t, std::vector<pair_t>, std::greater<pair_t>> pq;
            path_t path;
            distance_t dist;

            for (auto& temp : this->_g._unordered_vertices) {
                dist[temp] = graph_search::graph_infinite;
            }

            // this->visit(u);

            pq.push({0, u});
            dist[u] = 0;

            while (false == pq.empty()) {
                T v = pq.top().second;
                int d = pq.top().first;
                pq.pop();

                if (d > dist[v]) {
                    continue;
                }

                for (const auto& neighbour : neighbours.find(v)->second) {
                    int weight = this->get_weight(v, neighbour);
                    int distance = dist[v] + weight;
                    if (dist[neighbour] > distance) {
                        dist[neighbour] = distance;
                        pq.push({distance, neighbour});

                        path[neighbour].clear();  // clear longer one
                        path[neighbour].insert({distance, v});
                    } else if (dist[neighbour] == distance) {
                        path[neighbour].insert({distance, v});  // same distance
                    }
                }
            }

            _dist.insert({u, dist});
            _path.insert({u, path});
        }

        virtual void do_infer(const T& u) {
            route_t route;
            for (auto path : _path[u]) {
                const T& to = path.first;
                for (auto section : path.second) {
                    int distance = section.first;
                    const T& from = section.second;
                    auto iter = route.insert({edge(u, to, distance), std::list<T>()});
                    std::list<T>& l = iter->second;
                    l.push_back(from);
                    l.push_back(to);
                }
            }

            route_t route_branch;
            std::function<void(const edge& e, std::list<T>&)> filler;
            filler = [&](const edge& e, std::list<T>& lst) -> void {
                T head = *lst.begin();
                while (u != head) {
                    auto& section = _path[u].find(head)->second;
                    auto iter = section.begin();
                    head = iter->second;  // update head -- while (u != head)

                    for (iter++; iter != section.end(); iter++) {          // alternative section
                        std::list<T> list_branch = lst;                    // branch list
                        const T& head_branch = iter->second;               // select alternative neighbour
                        list_branch.push_front(head_branch);               // into branch list
                        filler(e, list_branch);                            // fill
                        route_branch.insert({e, std::move(list_branch)});  // insert branch list into branch route
                    }

                    lst.push_front(head);  // head into list
                }
            };

            for (auto& item : route) {
                const edge& e = item.first;
                auto& lst_origin = item.second;  // origin list
                filler(e, lst_origin);           // handle origin list or branch list if alternative available
            }
            for (auto& item : route_branch) {  // merge into route
                route.insert({item.first, std::move(item.second)});
            }
            _route.insert({u, route});
        }

        virtual void do_traverse(const T& u, visitor_t f) {
            for (auto route : _route[u]) {
                const edge& e = route.first;
                f(e._from, e._to, e._weight, route.second);
            }
        }
        virtual void do_traverse(const T& from, const T& to, visitor_t f) {
            route_t route = _route[from];
            edge e(from, to);
            auto lbound = route.lower_bound(e);
            auto ubound = route.upper_bound(e);
            for (auto iter = lbound; iter != ubound; iter++) {
                f(from, to, iter->first._weight, iter->second);
            }
        }

       private:
        typedef std::pair<int, T> pair_t;

        /*
         * @brief   distance
         * @sa      learn, _dist
         *
         * (gdb) p _dist
         * $1 = std::map with 1 element = {[0] = std::map with 9 elements =
         *       {[0] = 0, [1] = 4, [2] = 12, [3] = 19, [4] = 21, [5] = 11, [6] = 9, [7] = 8, [8] = 14}}
         *
         * it can be interpreted as from->to(weight)
         *      0->0(0), 0->1(4), 0->2(12), ..., 0->8(14)
         */
        typedef std::map<T, int> distance_t;

        /**
         * @brief   shortest path
         * @sa      learn, _path
         *
         * (gdb) p _path
         * $2 = std::map with 1 element = {[0] = std::map with 8 elements = {
         *       [1] = std::multimap with 1 element = {[4] = 0},
         *       [2] = std::multimap with 1 element = {[12] = 1},
         *       [3] = std::multimap with 1 element = {[19] = 2},
         *       [4] = std::multimap with 1 element = {[21] = 5},
         *       [5] = std::multimap with 1 element = {[11] = 6},
         *       [6] = std::multimap with 1 element = {[9] = 7},
         *       [7] = std::multimap with 1 element = {[8] = 0},
         *       [8] = std::multimap with 1 element = {[14] = 2}}}
         *
         *  it can be interpreted as from->to(weight) and prev->to
         *      0->1( 4) and 0->1, 0->2(12) and 1->2, ..., 0->8(14) and 2->8
         */
        typedef std::multimap<int, T> section_t;  // <distance, from>
        typedef std::map<T, section_t> path_t;    // map<to, section_t>

        /*
         * @brief   edge(from, to, distance) and list<T>
         * @sa      infer, _route
         *
         * gdb) p route
         * $3 = std::multimap with 8 elements = {
         *        [{_from = {_data = 0}, _to = {_data = 1}, _weight = 4,
         *            _direction = hotplace::graph_directed}] = std::__cxx11::list = {[0] = 0, [1] = 1},
         *        [{_from = {_data = 0}, _to = {_data = 2}, _weight = 12,
         *            _direction = hotplace::graph_directed}] = std::__cxx11::list = {[0] = 0, [1] = 1, [2] = 2},
         *        [{_from = {_data = 0}, _to = {_data = 3}, _weight = 19,
         *            _direction = hotplace::graph_directed}] = std::__cxx11::list = {[0] = 0, [1] = 1, [2] = 2, [3] = 3},
         *        [{_from = {_data = 0}, _to = {_data = 4}, _weight = 21,
         *            _direction = hotplace::graph_directed}] = std::__cxx11::list = {[0] = 0, [1] = 7, [2] = 6, [3] = 5, [4] = 4},
         *        [{_from = {_data = 0}, _to = {_data = 5}, _weight = 11,
         *            _direction = hotplace::graph_directed}] = std::__cxx11::list = {[0] = 0, [1] = 7, [2] = 6, [3] = 5},
         *        [{_from = {_data = 0}, _to = {_data = 6}, _weight = 9,
         *            _direction = hotplace::graph_directed}] = std::__cxx11::list = {[0] = 0, [1] = 7, [2] = 6},
         *        [{_from = {_data = 0}, _to = {_data = 7}, _weight = 8,
         *            _direction = hotplace::graph_directed}] = std::__cxx11::list = {[0] = 0, [1] = 7},
         *        [{_from = {_data = 0}, _to = {_data = 8}, _weight = 14,
         *            _direction = hotplace::graph_directed}] = std::__cxx11::list = {[0] = 0, [1] = 1, [2] = 2, [3] = 8}}
         */
        typedef std::multimap<edge, std::list<T>> route_t;

        std::map<T, distance_t> _dist;
        std::map<T, path_t> _path;
        std::map<T, route_t> _route;
    };

    graph_adjacent_list* build_adjacent() { return new graph_adjacent_list(*this); }
    graph_dfs* build_dfs() { return new graph_dfs(*this); }
    graph_bfs* build_bfs() { return new graph_bfs(*this); }
    graph_dijkstra* build_dijkstra() { return new graph_dijkstra(*this); }
};

}  // namespace hotplace

#endif
