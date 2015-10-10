module httpinterface.uestruct;



string URLEncodeStruct(T)(T value) if (is(T == struct)) {
	import std.traits;
	import std.array;
	import std.format;
	import std.conv;
	import std.uri;
	string[] output;
	foreach (member; FieldNameTuple!T) {
		assert(!is(typeof(__traits(getMember, value, member)) == struct), "Cannot URL encode nested structs");
		static if (isArray!(typeof(__traits(getMember, value, member))) && !isSomeString!(typeof(__traits(getMember, value, member)))) {
			output ~= format("%s=%s", encodeComponent(member), encodeComponent(format("%-(%s,%)", __traits(getMember, value, member))));
		} else
			output ~= format("%s=%s", encodeComponent(member), encodeComponent(__traits(getMember, value, member).to!string));
	}
	return output.join("&");
}

package string[][string] URLEncodeStructInternal(T)(T value) if (is(T == struct)) {
	import std.traits;
	import std.array;
	import std.format;
	import std.conv;
	string[][string] output;
	foreach (member; FieldNameTuple!T) {
		assert(!is(typeof(__traits(getMember, value, member)) == struct), "Cannot URL encode nested structs");
		static if (isArray!(typeof(__traits(getMember, value, member))) && !isSomeString!(typeof(__traits(getMember, value, member)))) {
			output[member] = [format("%-(%s,%)", __traits(getMember, value, member))];
		} else
			output[member] = [__traits(getMember, value, member).to!string];
	}
	return output;
}
unittest {
	struct beep {
		string a;
		uint b;
		uint[] c;
	}
	import std.stdio;
	assert(URLEncodeStruct(beep("treeee&", 3, [1,2,5])) == "a=treeee%26&b=3&c=1%2C2%2C5");
	assert(isURLEncodable!beep);
	assert(!isURLEncodable!uint);
}

template isURLEncodable(T) {
	enum isURLEncodable = __traits(compiles, { T thing; URLEncodeStruct(thing); });
}