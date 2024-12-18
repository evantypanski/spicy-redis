# @TEST-DOC: Test Zeek parsing pubsub commands
#
# @TEST-EXEC: zeek -Cr ${TRACES}/stream.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff redis.log

# Streams like with XRANGE return arrays of bulk strings. We shouldn't count the
# response as commands.
