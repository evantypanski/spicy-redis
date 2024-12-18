# @TEST-DOC: Test Zeek with RESP over TLS so it doesn't get gibberish
#
# @TEST-EXEC: zeek -Cr ${TRACES}/tls.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC-FAIL: test -f redis.log

# The logs should probably be empty since it's all encrypted
