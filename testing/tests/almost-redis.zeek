# @TEST-DOC: Test 2 commands that look like RESP, then server responses don't
#
# @TEST-EXEC: zeek -Cr ${TRACES}/almost-resp.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff redis.log
#
# Really, the first 2 ARE Redis. The later ones should not be logged because we
# realized it's not Redis. The output from the server is:
# +OK\r\n+OK\r\nnot RESP\r\nStill not RESP\r\nNope\r\n
