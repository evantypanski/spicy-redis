# @TEST-DOC: Test Zeek parsing pubsub commands
#
# @TEST-EXEC: zeek -Cr ${TRACES}/pubsub.trace ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff resp.log

# Testing the example of pub sub in REDIS docs:
# https://redis.io/docs/latest/develop/interact/pubsub/
# These are just commands between two different clients, one PUBLISH and one SUBSCRIBE.
event RESP::data(c: connection, is_orig: bool, payload: RESP::RESPData)
    {
    print fmt("Testing RESP pubsub response: %s", payload);
    }
