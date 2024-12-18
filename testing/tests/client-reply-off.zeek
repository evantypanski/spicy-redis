# @TEST-DOC: Test CLIENT REPLY OFF then ON again and a SKIP
#
# @TEST-EXEC: zeek -Cr ${TRACES}/reply-off-on.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff redis.log
