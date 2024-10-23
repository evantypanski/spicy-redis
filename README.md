# Spicy-based Redis analyzer

Parses the [Redis serialization protocol](https://redis.io/docs/latest/develop/reference/protocol-spec/) (RESP). Then parses this as Redis commands

## Usage

Common usage within Zeek.

First, build the analyzer:

```
$ mkdir build && cd build
$ cmake .. -G Ninja
$ ninja install
```

You should now see the spicy analyzer via `zeek`:

```
$ zeek -NN | grep Redis
    [Analyzer] spicy_redis (ANALYZER_SPICY_REDIS, enabled)
```

### Creating Redis traffic

You can easily create Redis traffic by grabbing the [redis CLI](https://redis.io/docs/latest/develop/connect/cli/). Just start a server with `redis-server` and connect to it with `redis-cli`. That will use the default port (6379) recognized by the provided Zeek script.

You can also create a [free REDIS server](https://redis.io/try-free/) and use that traffic, albeit on a provided port. There is also a "private" authorization that will be shown in the traffic.

When connecting via `redis-cli`, all commands are just sent as bulk strings in an array. So, all commands just get serialized via RESP.
