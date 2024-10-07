# @TEST-DOC: Test Zeek parsing pubsub commands
#
# @TEST-EXEC: zeek -Cr ${TRACES}/pubsub.trace ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff resp.log

# Testing the example of pub sub in REDIS docs:
# https://redis.io/docs/latest/develop/interact/pubsub/
# These are just commands between two different clients, one PUBLISH and one SUBSCRIBE.
event RESP::publish_command(c: connection, is_orig: bool, channel: string, message: string)
    {
    print fmt("Found publish to channel %s: %s", channel, message);
    }

event RESP::subscribe_command(c: connection, is_orig: bool, channel: string)
    {
    print fmt("Found subscribe to channel %s", channel);
    }
