module easyhttp.util;

import core.thread : Thread;
import core.time : Duration, msecs;
import std.datetime : Clock, SysTime;
import std.random : uniform;
import std.typecons : Nullable;

enum DelayType {
	random,
}

struct RequestDelay {
	DelayType type;
	Duration baseDuration;
	double range;
}
struct DelayState {
	Nullable!SysTime next;
}
private DelayState state;
void tryDelay(const RequestDelay delay) @safe {
	static void trustedSleep(Duration duration) @trusted {
		Thread.sleep(duration);
	}
	const now = Clock.currTime();
	if (state.next.get(SysTime.min) > now) {
		trustedSleep(state.next.get - now);
	}
	final switch (delay.type) {
		case DelayType.random:
			state.next = Clock.currTime + (cast(uint)(delay.baseDuration.total!"msecs" * uniform(1.0 - delay.range, 1.0 + delay.range))).msecs;
			break;
	}
}
