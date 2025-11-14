/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

#include <hotplace/sdk/odbc.hpp>

using namespace hotplace::odbc;

test_case _test_case;
t_shared_instance<logger> _logger;
t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

// connection strings
// DRIVER={%s};SERVER=%s,%ld;UID=%s;PWD=%s;DATABASE=%s;PROTOCOL=TCPIP;
// DRIVER={%s};HOSTNAME=%s;PORT=%ld;UID=%s;PWD=%s;DATABASE=%s;PROTOCOL=TCPIP;
// DRIVER={%s};HOSTNAME=%s;UID=%s;PWD=%s;DATABASE=%s;Network=dbnmpntw;
// DRIVER={%s};SERVER=%s;DATABASE=%s;Trusted_Connection=yes;
// DRIVER={%s};DBQ=%s;
// DRIVER={%s};SERVER=%s;PORT=%d;DATABASE=%s;USER=%s;PASSWORD=%s;OPTION=3;
// Driver={%s};Server=myServerAddress;Database=myDataBase;Uid=myUsername;Pwd=myPassword;

// Drivers
// SQL Server
// IBM DB2 ODBC DRIVER
// Microsoft ODBC for Oracle
// MySQL ODBC 3.51 Driver
// MySQL ODBC 5.3 ANSI Driver
// PostgreSQL
// SYBASE ASE ODBC Driver
// Microsoft dBASE Driver (*.dbf)
// Firebird/InterBase(r) driver
// Informix-CLI 2.5 (32 Bit)
// Microsoft Visual FoxPro Driver
// Microsoft Access Driver (*.mdb)
// Microsoft Excel Driver (*.xls)

return_t dbdiag_handler(DWORD native_error, const char* state, const char* message, bool* control, void* context) {
    return_t ret = errorcode_t::success;

    _logger->writeln("[native_error %i][sqlstate %s]%s", native_error, state, message);

    return ret;
}

void test() {
    return_t ret = errorcode_t::success;
    odbc_connector dbconn;
    odbc_query* rs = nullptr;

    odbc_diagnose::get_instance()->add_handler(dbdiag_handler, nullptr);

    const OPTION& option = _cmdline->value();
    _logger->writeln("connection string [%s]", option.connstr.c_str());

    ret = dbconn.connect(&rs, option.connstr.c_str());
    _test_case.test(ret, __FUNCTION__, "connect");

    if (errorcode_t::success == ret) {
        ret = rs->query("select * from %s", option.tablename.c_str());
        _test_case.test(ret, __FUNCTION__, "query");
        if (errorcode_t::success == ret) {
            odbc_record record;
            while (true) {
                while (errorcode_t::success == rs->fetch(&record)) {
                    _logger->writeln("---");
                    int n = record.count();
                    for (int i = 0; i < n; i++) {
                        odbc_field* field = record.get_field(i);
                        ansi_string f, d;
                        field->get_field_name(f);
                        field->as_string(d);
                        _logger->writeln("%s : %s", f.c_str(), d.c_str());
                    }
                }
                bool more = rs->more();
                if (false == more) {
                    break;
                }
            }
        }
        rs->release();
    }
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    (*_cmdline) << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.enable_verbose(); }).optional()
#if defined DEBUG
                << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION& o, char* param) -> void { o.enable_debug(); }).optional()
                << t_cmdarg_t<OPTION>("-D", "trace level 0|2", [](OPTION& o, char* param) -> void { o.enable_trace(atoi(param)); }).optional().preced()
                << t_cmdarg_t<OPTION>("--trace", "trace level [trace]", [](OPTION& o, char* param) -> void { o.enable_trace(loglevel_trace); }).optional()
                << t_cmdarg_t<OPTION>("--debug", "trace level [debug]", [](OPTION& o, char* param) -> void { o.enable_trace(loglevel_debug); }).optional()
#endif
                << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
                << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional()
                << t_cmdarg_t<OPTION>("--c", "connection string", [](OPTION& o, char* param) -> void { o.connstr = param; }).preced()
                << t_cmdarg_t<OPTION>("--t", "tablename", [](OPTION& o, char* param) -> void { o.tablename = param; }).preced();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose);
    if (option.log) {
        builder.set(logger_t::logger_flush_time, 1).set(logger_t::logger_flush_size, 1024).set_logfile("test.log").attach(&_test_case);
    }
    if (option.time) {
        builder.set_timeformat("[Y-M-D h:m:s.f]");
    }
    _logger.make_share(builder.build());

    if (option.debug) {
        auto lambda_tracedebug = [&](trace_category_t category, uint32 event, stream_t* s) -> void { _logger->write(s); };
        set_trace_debug(lambda_tracedebug);
        set_trace_option(trace_bt | trace_except | trace_debug);
        set_trace_level(option.trace_level);
    }

    test();

    _logger->flush();

    _test_case.report(5);
    return _test_case.result();
}
