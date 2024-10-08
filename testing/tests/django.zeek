# @TEST-DOC: Test Redis traffic from a django app using Redis as a cache
#
# @TEST-EXEC: zeek -Cr ${TRACES}/django-cache.trace ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff resp.log

event RESP::set_command(c: connection, is_orig: bool, command: RESP::SetCommand)
    {
    # Print the whole command because these have extra data that's worth capturing.
    print fmt("SET: %s %s expires in %d milliseconds", command$key, command$value, command$px);
    }
