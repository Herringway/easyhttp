module easyhttp.uestruct;

/++
 + URL-encodes a data structure.
 +
 + Translates a struct into a set of key-value pairs appropriate for use in 
 + x-www-form-urlencoded POSTs and URLs. Each pair is rendered as key=value and
 + delimited by &s. All characters, except for a-z, A-Z, 0-9, and -_.~, will be
 + represented in the form %xx where xx is the hexadecimal value of each byte in
 + the character.
 + 
 + Standards: RFC3986
 + Params:
 +  value = The structure to encode
 +/
string urlEncodeStruct(T)(T value) if (is(T == struct)) {
	import std.traits : isSomeString, isArray, FieldNameTuple;
	import std.format : format;
	import std.conv : text;
	import std.array : join;
	import std.uri : encodeComponent;
	string[] output;
	foreach (member; FieldNameTuple!T) {
		assert(!is(typeof(__traits(getMember, value, member)) == struct), "Cannot URL encode nested structs");
		static if (isArray!(typeof(__traits(getMember, value, member))) && !isSomeString!(typeof(__traits(getMember, value, member)))) {
			output ~= format("%s=%s", encodeComponent(member), encodeComponent(format("%-(%s,%)", __traits(getMember, value, member))));
		} else
			output ~= format("%s=%s", encodeComponent(member), encodeComponent(__traits(getMember, value, member).text));
	}
	return output.join("&");
}

package string[][string] urlEncodeStructInternal(T)(T value) if (is(T == struct)) {
	import std.traits : isSomeString, isArray, FieldNameTuple;
	import std.format : format;
	import std.conv : text;
	string[][string] output;
	foreach (member; FieldNameTuple!T) {
		assert(!is(typeof(__traits(getMember, value, member)) == struct), "Cannot URL encode nested structs");
		static if (isArray!(typeof(__traits(getMember, value, member))) && !isSomeString!(typeof(__traits(getMember, value, member)))) {
			output[member] = [format("%-(%s,%)", __traits(getMember, value, member))];
		} else
			output[member] = [__traits(getMember, value, member).text];
	}
	return output;
}
unittest {
	struct Beep {
		string a;
		uint b;
		uint[] c;
	}
	assert(urlEncodeStruct(Beep("treeee&", 3, [1,2,5])) == "a=treeee%26&b=3&c=1%2C2%2C5");
}
/++
 + Detect whether or not a type T is URL-encodable.
 +
 + Any struct without nested structs is compatible.
 +
 + Params:
 +  T = type to test
 +/
template isURLEncodable(T) {
	enum isURLEncodable = __traits(compiles, { T thing; urlEncodeStruct(thing); });
}
///
unittest {
	struct Test {
		string a;
	}
	assert(isURLEncodable!Test);
	assert(!isURLEncodable!uint);
}