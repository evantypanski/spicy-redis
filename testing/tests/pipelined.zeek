# @TEST-DOC: Test Zeek parsing "pipelined" data responses
#
# @TEST-EXEC: zeek -Cr ${TRACES}/pipelining-example.trace ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output

# Testing the example of "pipelining" in REDIS docs:
# https://redis.io/docs/latest/develop/use/pipelining/
# Namely sending three PINGs. This does not get sent as RESP data, but we should
# be able to skip it and get the responses, which are properly encoded.
#
# Note that without a data event, this test is next to useless, but hopefully
# it catches the parser getting sent into a bad state from the unserialized data.
#
# Also, you can send serialized data this way - that's kinda what the bulk test does.
