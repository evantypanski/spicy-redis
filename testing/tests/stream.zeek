# @TEST-DOC: Test Zeek parsing pubsub commands
#
# @TEST-EXEC: zeek -Cr ${TRACES}/stream.trace ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff resp.log

# Streams like with XRANGE return arrays of bulk strings. We shouldn't count the
# response as commands.
