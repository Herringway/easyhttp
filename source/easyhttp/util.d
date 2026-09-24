module easyhttp.util;

import core.thread : Thread;
import core.time;
import std.algorithm.iteration;
import std.algorithm.searching;
import std.conv;
import std.datetime;
import std.exception;
import std.random;
import std.typecons : Nullable;

enum DelayType {
	random,
	periodLimited,
}

struct RequestDelay {
	DelayType type;
	Duration baseDuration;
	double range = 0.0;
	int limitCount;
}
struct DelayState {
	Nullable!SysTime next;
	SysTime[] recentRequests;
	Duration tryDelay(const RequestDelay delay, const SysTime now, Random rng) @safe pure {
		if (next.get(SysTime.min) > now) {
			recentRequests ~= next.get();
			return next.get - now;
		}
		while ((recentRequests.length > 0) && (recentRequests[0] <= now - delay.baseDuration)) {
			recentRequests = recentRequests[1 .. $];
		}
		final switch (delay.type) {
			case DelayType.periodLimited:
				if (recentRequests.length < delay.limitCount) {
					next = now;
				} else {
					next = recentRequests[0] + delay.baseDuration;
				}
				break;
			case DelayType.random:
				next = now + (cast(uint)(delay.baseDuration.total!"msecs" * uniform(1.0 - delay.range, 1.0 + delay.range, rng))).msecs;
				break;
		}
		recentRequests ~= next.get(now);
		return next.get(now) - now;
	}
}

@safe pure unittest {
	Random rng;
	const now = SysTime(0);
	{
		DelayState state;
		const delay =  RequestDelay(type: DelayType.periodLimited, baseDuration: 100.msecs, limitCount: 1);
		assert(state.tryDelay(delay, now, rng) == 0.msecs);
		assert(state.tryDelay(delay, now+1.msecs, rng) == 99.msecs);
		assert(state.tryDelay(delay, now+100.msecs, rng) == 100.msecs);
		assert(state.tryDelay(delay, now+300.msecs, rng) == 0.msecs);
	}
}

DateTime httpDate(const(char)[] str) @safe pure {
	static immutable months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
	auto splitStr = str.splitter(" ");
	splitStr.popFront(); // skip the day of the week
	int day = splitStr.front.to!int;
	splitStr.popFront(); // now at month
	int month = cast(int)months.countUntil(splitStr.front) + 1;
	splitStr.popFront(); // now at year
	int year = splitStr.front.to!int;
	splitStr.popFront(); // now at timestamp
	auto splitTime = splitStr.front.splitter(":");
	int hour = splitTime.front.to!int;
	splitTime.popFront(); // timestamp now at minute
	int minute = splitTime.front.to!int;
	splitTime.popFront(); // timestamp now at second
	int second = splitTime.front.to!int;
	splitStr.popFront(); // now at timezone (always GMT)
	enforce(splitStr.front == "GMT", "Invalid Date header");
	return DateTime(year, month, day, hour, minute, second);
}
@safe pure unittest {
	assert(httpDate("Wed, 21 Oct 2015 07:28:00 GMT") == DateTime(2015, 10, 21, 7, 28, 0));
}