# @TEST-DOC: Test Zeek parsing a trace file through the RESP analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/loop-redis.trace ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff resp.log

event RESP::set_command(c: connection, is_orig: bool, command: RESP::SetCommand)
    {
    print fmt("SET: %s %s", command$key, command$value);
    }

event RESP::get_command(c: connection, is_orig: bool, command: RESP::GetCommand)
    {
    print fmt("GET: %s", command);
    }
