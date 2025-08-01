module easyhttp.cookies;

import std.range;

struct Cookie {
	string domain;
	string path;
	string key;
	string value;
	void toString(T)(T sink) const if (isOutputRange!(T, char[])) {
		import std.format : formattedWrite;
		sink.formattedWrite!"%s=%s"(key, value);
	}
}
