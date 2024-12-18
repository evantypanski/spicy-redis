# @TEST-DOC: Test Zeek parsing a trace file through the Redis analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/loop-redis.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff redis.log

event Redis::set_command(c: connection, is_orig: bool,
    command: Redis::SetCommand)
	{
	print fmt("SET: %s %s", command$key, command$value);
	}

event Redis::get_command(c: connection, is_orig: bool,
    command: Redis::GetCommand)
	{
	print fmt("GET: %s", command);
	}
