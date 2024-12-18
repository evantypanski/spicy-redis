# @TEST-DOC: Test CLIENT REPLY OFF, but turns on with new connection
#
# @TEST-EXEC: zeek -Cr ${TRACES}/reply-off-on-2conn.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff redis.log
