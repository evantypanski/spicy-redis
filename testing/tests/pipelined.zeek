# @TEST-DOC: Test Zeek parsing "pipelined" data responses
#
# @TEST-EXEC: zeek -Cr ${TRACES}/pipelining-example.trace ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff resp.log

# Testing the example of "pipelining" in REDIS docs:
# https://redis.io/docs/latest/develop/use/pipelining/
# Namely sending three PINGs. This does not get sent as RESP data, but we should
# be able to skip it and get the responses, which are properly encoded.
event RESP::data(c: connection, is_orig: bool, payload: RESP::RESPData)
    {
    print fmt("Testing RESP pipelining response: %s", payload);
    }
