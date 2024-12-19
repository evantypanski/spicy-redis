# Spicy-based Redis analyzer

Parses the [Redis serialization protocol](https://redis.io/docs/latest/develop/reference/protocol-spec/) (RESP). Then parses this as Redis commands

## Installation

Install using the [Zeek package manager](https://docs.zeek.org/projects/package-manager/en/stable/), `zkg`:

```
zkg install https://github.com/evantypanski/spicy-redis
```

Check to ensure it installed properly:

```
$ zeek -NN | grep spicy_Redis
    [Analyzer] spicy_Redis (ANALYZER_SPICY_REDIS, enabled)
```

### From source

You can also build from source directly from this directory, then install the local version:

```
$ mkdir build && cd build
$ cmake .. -G Ninja
$ ninja install
```

## Usage

When installing this through `zkg`, the package's scripts will be available with `spicy-redis.git` - so you can run `zeek` with the scripts like:

```
$ zeek -Cr testing/Traces/set.trace spicy-redis.git
$ cat redis.log
# ... the log output should appear
```

If it's elsewhere, check your `zkg` `script_dir`

### Creating Redis traffic

You can easily create Redis traffic by grabbing the [redis CLI](https://redis.io/docs/latest/develop/connect/cli/). Just start a server with `redis-server` and connect to it with `redis-cli`. That will use the default port (6379) recognized by the provided Zeek script.

You can also create a [free REDIS server](https://redis.io/try-free/) and use that traffic, albeit on a provided port. There is also a "private" authorization that will be shown in the traffic.

When connecting via `redis-cli`, all commands are just sent as bulk strings in an array. So, all commands just get serialized via RESP.
