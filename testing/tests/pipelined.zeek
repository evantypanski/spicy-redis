# @TEST-DOC: Test Zeek parsing "pipelined" data responses
#
# @TEST-EXEC: zeek -Cr ${TRACES}/pipelining-example.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff redis.log

# Testing the example of "pipelining" in REDIS docs:
# https://redis.io/docs/latest/develop/use/pipelining/
# Namely sending three PINGs. This does not get sent as RESP data, but we should
# be able to skip it and get the responses, which are properly encoded.
#
# Also, you can send serialized data this way - that's kinda what the bulk test does.
