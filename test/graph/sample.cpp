/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <algorithm>
#include <functional>
#include <sdk/nostd.hpp>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;

    _OPTION() : verbose(0) {
        // do nothing
    }
} OPTION;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

template <typename T>
void do_test_graph(t_graph<T>& graph, const T& start) {
    auto traverse_handler = [](const T& from, const T&, int, const std::list<T>& v) -> void {
        basic_stream bs;
        print<std::list<T>, basic_stream>(v, bs, "", ", ", "");
        basic_stream out;
        out << from << " : " << bs;
        _logger->writeln(out);
    };

    auto adj = graph.build_adjacent();
    adj->learn().infer();
    adj->traverse(traverse_handler);
    _test_case.assert(true, __FUNCTION__, "adjacent list #1");
    adj->traverse(start, traverse_handler);
    _test_case.assert(true, __FUNCTION__, "adjacent list #2");
    delete adj;

    auto dfs = graph.build_dfs();
    dfs->learn().infer();
    dfs->traverse(traverse_handler);
    _test_case.assert(true, __FUNCTION__, "DFS #1");
    dfs->traverse(start, traverse_handler);
    _test_case.assert(true, __FUNCTION__, "DFS #2");
    delete dfs;

    auto bfs = graph.build_bfs();
    bfs->learn().infer();
    bfs->traverse(traverse_handler);
    _test_case.assert(true, __FUNCTION__, "BFS #1");
    bfs->traverse(start, traverse_handler);
    _test_case.assert(true, __FUNCTION__, "BFS #2");
    delete bfs;
}

template <typename T>
void do_test_graph_shortest_path(t_graph<T>& graph, const T& start) {
    auto traverse_handler = [](const T& from, const T& to, int distance, const std::list<T>& v) -> void {
        basic_stream bs;
        print<std::list<T>, basic_stream>(v, bs, "", " -> ", "");
        basic_stream out;
        out << "path[" << from << "->" << to << "] " << bs << " (distance : " << distance << ")";
        _logger->writeln(out);
    };

    auto shortest = graph.build_dijkstra();
    shortest->learn().infer();
    shortest->traverse(start, traverse_handler);  // [start]
    _test_case.assert(true, __FUNCTION__, "shortest path");
    delete shortest;
}
template <typename T>
void do_test_graph_shortest_path(t_graph<T>& graph, const T& start, const T& end) {
    auto traverse_handler = [&](const T& from, const T& to, int distance, const std::list<T>& v) -> void {
        basic_stream bs;
        print<std::list<T>, basic_stream>(v, bs, "", " -> ", "");
        basic_stream out;
        out << "path[" << from << "->" << to << "] " << bs << " (distance : " << distance << ")";
        _logger->writeln(out);
    };

    auto shortest = graph.build_dijkstra();
    shortest->learn().infer();
    shortest->traverse(start, end, traverse_handler);  // [start-end]
    _test_case.assert(true, __FUNCTION__, "shortest path");
    delete shortest;
}

void test_graph() {
    _test_case.begin("graph<int>");

    // Data Structures and Algorithm Analysis in C++, 9 Graph Algorithms
    // directed.jpg
    t_graph<int> g;
    g.add_edge(1, 2)
        .add_directed_edge(1, 3)
        .add_directed_edge(1, 4)
        .add_directed_edge(2, 4)
        .add_directed_edge(2, 5)
        .add_directed_edge(3, 6)
        .add_directed_edge(4, 3)
        .add_directed_edge(4, 6)
        .add_directed_edge(4, 7)
        .add_directed_edge(5, 4)
        .add_directed_edge(5, 7)
        .add_directed_edge(7, 6);

    // Shortest-Path Algorithms
    // undirected.jpg
    t_graph<int> g2;
    g2.add_undirected_edge(0, 1, 4)
        .add_undirected_edge(0, 7, 8)
        .add_undirected_edge(1, 7, 11)
        .add_undirected_edge(1, 2, 8)
        .add_undirected_edge(7, 8, 7)
        .add_undirected_edge(7, 6, 1)
        .add_undirected_edge(2, 8, 2)
        .add_undirected_edge(8, 6, 6)
        .add_undirected_edge(2, 3, 7)
        .add_undirected_edge(2, 5, 4)
        .add_undirected_edge(6, 5, 2)
        .add_undirected_edge(3, 5, 14)
        .add_undirected_edge(3, 4, 9)
        .add_undirected_edge(5, 4, 10);

    do_test_graph<int>(g, 1);
    for (auto i = 1; i <= 7; i++) {
        do_test_graph_shortest_path<int>(g, i);
    }
    do_test_graph<int>(g2, 1);
    for (auto i = 0; i <= 8; i++) {
        do_test_graph_shortest_path<int>(g2, i);
    }

    t_graph<int> g3;
    g3.add_undirected_edge(1, 2)
        .add_undirected_edge(2, 3)
        .add_undirected_edge(3, 4)
        .add_undirected_edge(4, 5)
        .add_undirected_edge(5, 6)
        .add_undirected_edge(6, 3)
        .add_undirected_edge(3, 7)
        .add_undirected_edge(7, 1);
    do_test_graph<int>(g3, 1);
    for (auto i = 1; i <= 7; i++) {
        do_test_graph_shortest_path<int>(g3, i);
    }
    do_test_graph_shortest_path<int>(g3, 1, 5);
}

/*
 *  @sa     User-defined literals (since C++11)
 */
int operator"" _min(unsigned long long int x) { return x; }
int operator"" _hour(unsigned long long int x) { return x * 60; }
int operator"" _hour(long double x) { return x * 60; }

void test_graph2() {
    _test_case.begin("graph<std::string>");
    t_graph<std::string> g;

    g.add_edge("get up", "eat breakfast", 15_min);

    g.add_edge("eat breakfast", "brush teeath (morning)", 3_min);
    g.add_edge("eat breakfast", "go to work", 1_hour);

    g.add_edge("go to work", "work", 8_hour);
    g.add_edge("work", "go home", 1_hour);

    g.add_edge("go home", "shower", 15_min);
    g.add_edge("shower", "eat dinner", 15_min);

    g.add_edge("eat dinner", "brush teeath (evening)", 3_min);
    g.add_edge("eat dinner", "watch tv", 1.5_hour);
    g.add_edge("eat dinner", "go to bed", 0.5_hour);

    g.add_edge("go to bed", "dream", 3_min);

    do_test_graph<std::string>(g, "get up");
    do_test_graph_shortest_path<std::string>(g, "get up");
    do_test_graph_shortest_path<std::string>(g, "get up", "dream");
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    *_cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    test_graph();
    test_graph2();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
