# @TEST-DOC: Test that Redis does not parse if it starts with the server data
#
# @TEST-EXEC: zeek -Cr ${TRACES}/start-with-server.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output

event Redis::command(c: connection, is_orig: bool, command: Redis::Command)
	{
	print "BAD", command;
	}

event Redis::server_data(c: connection, is_orig: bool, dat: Redis::ServerData)
	{
	print "BAD", dat;
	}
