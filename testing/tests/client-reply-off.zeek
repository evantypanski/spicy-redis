# @TEST-DOC: Test CLIENT REPLY OFF then ON again and a SKIP
#
# @TEST-EXEC: zeek -Cr ${TRACES}/reply-off-on.trace ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff resp.log
