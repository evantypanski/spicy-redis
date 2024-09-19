# Spicy-based RESP analyzer

Parses the [Redis serialization protocol](https://redis.io/docs/latest/develop/reference/protocol-spec/) (RESP).

## Usage

1) Grab a PCAP (like [redis.pcap](https://github.com/macbre/data-flow-graph/blob/master/sources/pcap/redis.pcap))
2) Compile the code so Zeek can use it: `spicyz -o resp.hlto resp.spicy resp.evt`
3) See some output via Zeek: `zeek -C -r redis.pcap resp.hlto Spicy::enable_print=T`

This will be updated as it's better :)
