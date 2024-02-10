module easyhttp.util;

import core.thread : Thread;
import core.time;
import std.datetime;
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
DelayState globalDelay;
struct DelayState {
	Nullable!SysTime next;
	SysTime[] recentRequests;
	void tryDelay(const RequestDelay delay) @safe {
		static void trustedSleep(Duration duration) @trusted {
			Thread.sleep(duration);
		}
		const duration = tryDelay(delay, Clock.currTime, rndGen);
		if (duration > 0.msecs) {
			trustedSleep(duration);
		}
	}
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
