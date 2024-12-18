# @TEST-DOC: Test Zeek with AUTH commands
#
# @TEST-EXEC: zeek -Cr ${TRACES}/auth.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output

event Redis::auth_command(c: connection, is_orig: bool,
    command: Redis::AuthCommand)
	{
	print "AUTH";
	if ( command?$username )
		print fmt("username: %s", command$username);
	else
		print "username: default";

	print fmt("password: %s", command$password);
	}
