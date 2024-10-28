@load base/protocols/conn/removal-hooks

module Redis;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## The ports to register Redis for.
	const ports = { 6379/tcp } &redef;

	type SetCommand: record {
		key: string &log;
		value: string &log;
		nx: bool;
		xx: bool;
		get: bool;
		ex: count &optional;
		px: count &optional;
		exat: count &optional;
		pxat: count &optional;
		keep_ttl: bool;
	};

	type GetCommand: record {
		key: string &log;
	};

	type Command: record {
		## The raw command, exactly as parsed
		raw: vector of string;
		## The first element of the command. Some commands are two strings, meaning this
		## is inaccurate for those cases.
		command: string &log;
		## The key, if this command is known to have a key
		key: string &log &optional;
		## The value, if this command is known to have a value
		value: string &log &optional;
		## The command in an enum if it was known
		known: Redis::KnownCommand &optional;
	};

	type ServerData: record {
		## Was this an error?
		err: bool &log;
		## The string response, if it was a simple string or error
		data: string &log &optional;
	};

	## Record type containing the column fields of the Redis log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		## The Redis command
		cmd: Command &log &optional;
		## The response for the command
		response: ServerData &log &optional;
	};

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Default hook into Redis logging.
	global log_resp: event(rec: Info);

	global finalize_redis: Conn::RemovalHook;

	type State: record {
		## Pending requests.
		pending:          table[count] of Info;
		## Current request in the pending queue.
		current_request:  count &default=0;
		## Current response in the pending queue.
		current_response: count &default=0;
		## Ranges where we do not expect a response
		## Each range is one or two elements, one meaning it's unbounded, two meaning
		## it begins at one and ends at the second.
		no_response_ranges: vector of vector of count;
	};

}

redef record connection += {
	# TODO: Rename
	redis_resp: Info &optional;
	redis_state: State &optional;
};

redef likely_server_ports += { ports };

# TODO: If you're going to send file data into the file analysis framework, you
# need to provide a file handle function. This is a simple example that's
# sufficient if the protocol only transfers a single, complete file at a time.
#
# function get_file_handle(c: connection, is_orig: bool): string
#   {
#   return cat(Analyzer::ANALYZER_SPICY_REDIS, c$start_time, c$id, is_orig);
#   }

event zeek_init() &priority=5
	{
	Log::create_stream(Redis::LOG, [ $columns=Info, $ev=log_resp, $path="resp",
	    $policy=log_policy ]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_SPICY_REDIS, ports);

	# TODO: To activate the file handle function above, uncomment this.
	# Files::register_protocol(Analyzer::ANALYZER_SPICY_REDIS, [$get_file_handle=Redis::get_file_handle ]);
	}

function new_redis_session(c: connection): Info
	{
	return Info($ts=network_time(), $uid=c$uid, $id=c$id);
	}

function set_state(c: connection, is_orig: bool)
	{
	if ( ! c?$redis_state )
		{
		local s: State;
		c$redis_state = s;
		Conn::register_removal_hook(c, finalize_redis);
		}

	if ( is_orig )
		{
		if ( c$redis_state$current_request !in c$redis_state$pending )
			c$redis_state$pending[c$redis_state$current_request] = new_redis_session(c);

		c$redis_resp = c$redis_state$pending[c$redis_state$current_request];
		}
	else
		{
		if ( c$redis_state$current_response !in c$redis_state$pending )
			c$redis_state$pending[c$redis_state$current_response] = new_redis_session(c);

		c$redis_resp = c$redis_state$pending[c$redis_state$current_response];
		}
	}

event Redis::command(c: connection, is_orig: bool, command: Command)
	{
	#hook set_session(c, command);

	# TODO: We need to care about whether the reply was suppressed with
	# CLIENT REPLY [OFF|SKIP]
	#local info = c$redis_resp;
	#emit_log(c);
	# TODO refactor this since it's used a couple times
	if ( ! c?$redis_state )
		{
		local s: State;
		c$redis_state = s;
		Conn::register_removal_hook(c, finalize_redis);
		}

	++c$redis_state$current_request;
	if ( command?$known && command$known == KnownCommand_CLIENT )
		{
		# All 3 CLIENT commands we care about have 3 elements
		if ( |command$raw| == 3 )
			{
			if ( to_lower(command$raw[2]) == "on" )
				{
				# If the last range is open, close it here. Otherwise, noop
				if  ( |c$redis_state$no_response_ranges| > 0 )
					{
					local range = c$redis_state$no_response_ranges[|c$redis_state$no_response_ranges| - 1];
					if ( |range| == 1 )
						{
						range += c$redis_state$current_request;
						}
					}
				}
			if ( to_lower(command$raw[2]) == "off" )
				{
				# Only add a new interval if the last one is closed
				if  ( |c$redis_state$no_response_ranges| == 0 || |c$redis_state$no_response_ranges[|c$redis_state$no_response_ranges| - 1]| != 1)
					{
					c$redis_state$no_response_ranges += vector(c$redis_state$current_request);
					}
				}
			if ( to_lower(command$raw[2]) == "skip" )
				{
				# TODO: Test logic here, what if it's off the skip - does it close the
				# next one? For now this just introduces a new range of length 1
				c$redis_state$no_response_ranges += vector(c$redis_state$current_request, c$redis_state$current_request + 1);
				}
			}
		}
	set_state(c, T);

	c$redis_resp$cmd = command;
	}

## Gets the next response number based on a connection. This is necessary since
## some responses may have been skipped.
function response_num(c: connection): count
	{
	local resp_num = c$redis_state$current_response + 1;
	for ( i in c$redis_state$no_response_ranges )
		{
		local range = c$redis_state$no_response_ranges[i];
		assert |range| >= 1;
		if ( |range| == 1 && resp_num > range[0] )
			{} # TODO: This is necessary if not using pipelining
		if ( |range| == 2 && resp_num >= range[0]  && resp_num < range[1] )
			return range[1];
		}

	# Default: no disable/enable shenanigans
	return resp_num;
	}

event Redis::server_data(c: connection, is_orig: bool, data: ServerData)
	{
	if ( ! c?$redis_state )
		{
		local s: State;
		c$redis_state = s;
		Conn::register_removal_hook(c, finalize_redis);
		}
	c$redis_state$current_response = response_num(c);
	set_state(c, F);

	c$redis_resp$response = data;
	Log::write(Redis::LOG, c$redis_resp);
	delete c$redis_state$pending[c$redis_state$current_response];
	}

hook finalize_redis(c: connection)
	{
	# Flush all pending but incomplete request/response pairs.
	if ( c?$redis_state )
		{
		for ( r, info in c$redis_state$pending )
			{
			# We don't use pending elements at index 0.
			if ( r == 0 ) next;
			Log::write(Redis::LOG, info);
			}
		}
	}
