# @TEST-DOC: Test Zeek parsing a trace file through the RESP analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/tcp-port-12345.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff resp.log

# TODO: Adapt as suitable. The example only checks the output of the event
# handlers.

event RESP::message(c: connection, is_orig: bool, payload: string)
    {
    print fmt("Testing RESP: [%s] %s %s", (is_orig ? "request" : "reply"), c$id, payload);
    }
