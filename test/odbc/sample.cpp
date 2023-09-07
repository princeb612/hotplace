/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/sdk.hpp>
#include <stdio.h>
#include <iostream>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::odbc;

test_case _test_case;

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

return_t dbdiag_handler (DWORD native_error, const char* state, const char* message, bool* control, void* context)
{
    return_t ret = errorcode_t::success;

    printf ("[native_error %i][sqlstate %s]%s\n", native_error, state, message);

    return ret;
}

void test ()
{
    return_t ret = errorcode_t::success;
    odbc_connector dbconn;
    odbc_query* rs = nullptr;

    const char* connstrfmt = "DRIVER={%s};SERVER=%s;PORT=%d;DATABASE=%s;USER=%s;PASSWORD=%s";

    odbc_diagnose::get_instance ()-> add_handler (dbdiag_handler, nullptr);

    ret = dbconn.connect (&rs, format (connstrfmt, "MySQL ODBC 8.0 ANSI Driver", "localhost", 3306, "world", "user", "password").c_str ());
    if (ERROR_SUCCESS == ret) {
        ret = rs->query ("select * from city");
        if (ERROR_SUCCESS == ret) {
            odbc_record record;
            while (true) {
                while (ERROR_SUCCESS == rs->fetch (&record)) {
                    std::cout << "---" << std::endl;
                    int n = record.count ();
                    for (int i = 0; i < n; i++) {
                        odbc_field* field = record.get_field (i);
                        ansi_string f, d;
                        field->get_field_name (f);
                        field->as_string (d);
                        std::cout << f.c_str () << " : " << d.c_str () << std::endl;
                    }
                }
                bool more = rs->more ();
                if (false == more) {
                    break;
                }
            }
        }
        rs->release ();
    }
}

int main ()
{
    test ();

    _test_case.report (5);
    return _test_case.result ();
}
