# @TEST-DOC: Test Zeek parsing "pipelined" data responses
#
# @TEST-EXEC: zeek -Cr ${TRACES}/excessive-pipelining.trace ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff redis.log
# @TEST-EXEC: btest-diff weird.log

# Make sure we get a weird if we go over the pipelining threshold (intentionally limited)
redef Redis::max_pending_requests = 5;
