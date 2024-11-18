/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <signal.h>

#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;

test_case _test_case;
t_shared_instance<logger> _logger;
return_t _cmdret = errorcode_t::success;

typedef struct _OPTION {
    int verbose;
    int log;
    int time;

    _OPTION() : verbose(0), log(0), time(0) {}
} OPTION;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

#if defined __linux__
#if __GLIBC__ > 4

enum PROCESS_QUERY {
    PROCESS_QUERY_FILEPATH = 0, /* file path and name */
    PROCESS_QUERY_DIR,          /* file path */
    PROCESS_QUERY_CMDLINE,
};

#define BUFSIZE256 (1 << 8)

return_t query(pid_t pid, int id, std::string& value) {
    return_t ret = errorcode_t::success;

    value.clear();
    char buf[BUFSIZE256];
    int ret_read = 0;

    switch (id) {
        case PROCESS_QUERY_FILEPATH: {
            memset(buf, 0, sizeof(buf));
            /* "/proc/%d/exe" */
            constexpr char STRING__PROC__D_EXE[] = "/proc/%d/exe";
            ret_read = readlink(format(STRING__PROC__D_EXE, pid).c_str(), buf, RTL_NUMBER_OF(buf));
            if (-1 == ret_read) {
                ret = get_lasterror(errno);
            } else {
                value.assign(buf, ret_read);
            }
        } break;
        case PROCESS_QUERY_DIR: {
            memset(buf, 0, sizeof(buf));
            /* "/proc/%d/exe" */
            constexpr char STRING__PROC__D_EXE[] = "/proc/%d/exe";
            ret_read = readlink(format(STRING__PROC__D_EXE, pid).c_str(), buf, RTL_NUMBER_OF(buf));
            ret = get_lasterror(ret_read);
            if (errorcode_t::success == ret) {
                std::string source(buf, ret_read);
                value = source.substr(0, source.find_last_of('/'));
            }
        } break;
        case PROCESS_QUERY_CMDLINE: {
            /* "/proc/%d/cmdline" */
            constexpr char STRING__PROC__D_CMDLINE[] = "/proc/%d/cmdline";

            FILE* file = NULL;
            file = fopen(format(STRING__PROC__D_CMDLINE, pid).c_str(), "rb");
            if (NULL != file) {
                while (1) {
                    ret_read = fread(buf, 1, sizeof(buf), file);
                    if (0 >= ret_read) {
                        break;
                    }
                    value.append(buf, ret_read);
                }
                fclose(file);
            }
        } break;
        default:
            ret = errorcode_t::not_supported;
            break;
    }
    return ret;
}

return_t netlink_handler(uint32 type, void* data, void* parameter) {
    PROC_EVENT* event = static_cast<PROC_EVENT*>(data);

    std::string exe;
    std::string cmdline;
    switch (event->proc_ev.what) {
        case proc_event::PROC_EVENT_NONE:
            printf("set mcast listen ok\n");
            break;
        case proc_event::PROC_EVENT_FORK:
            printf("fork: parent tid=%d pid=%d -> child tid=%d pid=%d\n", event->proc_ev.event_data.fork.parent_pid, event->proc_ev.event_data.fork.parent_tgid,
                   event->proc_ev.event_data.fork.child_pid, event->proc_ev.event_data.fork.child_tgid);
            break;
        case proc_event::PROC_EVENT_EXEC:
            query(event->proc_ev.event_data.exec.process_pid, PROCESS_QUERY_FILEPATH, exe);
            query(event->proc_ev.event_data.exec.process_pid, PROCESS_QUERY_CMDLINE, cmdline);
            printf("exec: tid=%d pid=%d %s [%s]\n", event->proc_ev.event_data.exec.process_pid, event->proc_ev.event_data.exec.process_tgid, exe.c_str(),
                   cmdline.c_str());
            break;
        case proc_event::PROC_EVENT_UID:
            printf("uid change: tid=%d pid=%d from %d to %d\n", event->proc_ev.event_data.id.process_pid, event->proc_ev.event_data.id.process_tgid,
                   event->proc_ev.event_data.id.r.ruid, event->proc_ev.event_data.id.e.euid);
            break;
        case proc_event::PROC_EVENT_GID:
            printf("gid change: tid=%d pid=%d from %d to %d\n", event->proc_ev.event_data.id.process_pid, event->proc_ev.event_data.id.process_tgid,
                   event->proc_ev.event_data.id.r.rgid, event->proc_ev.event_data.id.e.egid);
            break;
        case proc_event::PROC_EVENT_EXIT:
            printf("exit: tid=%d pid=%d exit_code=%d\n", event->proc_ev.event_data.exit.process_pid, event->proc_ev.event_data.exit.process_tgid,
                   event->proc_ev.event_data.exit.exit_code);

            break;
        default:
            printf("unhandled proc event\n");
            break;
    }
    return 0;
}

semaphore sem;

void int_handler(int) { sem.signal(); }

return_t sighandler(int signo, void (*callback)(int)) {
    return_t ret = errorcode_t::success;

    __try2 {
        struct sigaction sig;

        sig.sa_handler = callback;
        sigemptyset(&sig.sa_mask);
        sig.sa_flags = 0;

        sigaction(signo, &sig, 0);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void test_netlink() {
    netlink_t* handle = NULL;
    netlink nl;
    nl.open(&handle, 0, netlink_handler, NULL);
    sighandler(SIGINT, int_handler);

    sem.wait(-1);

    nl.close(handle);
}
#endif
#endif

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);

    (*_cmdline) << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
                << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
                << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional();

    _cmdret = _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose);
    if (option.log) {
        builder.set(logger_t::logger_flush_time, 1).set(logger_t::logger_flush_size, 1024).set_logfile("test.log");
    }
    if (option.time) {
        builder.set_timeformat("[Y-M-D h:m:s.f]");
    }
    _logger.make_share(builder.build());

#if defined _WIN32 || defined _WIN64
    winsock_startup();
#endif

#if defined __linux__
#if __GLIBC__ > 4
    test_netlink();
#endif
#endif

    _logger->flush();

#if defined _WIN32 || defined _WIN64
    winsock_cleanup();
#endif

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
