# @TEST-DOC: Test Redis traffic from a django app using Redis as a cache
#
# @TEST-EXEC: zeek -Cr ${TRACES}/django-cache.trace ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff resp.log
