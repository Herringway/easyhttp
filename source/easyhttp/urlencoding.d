module easyhttp.urlencoding;

/++
 + URL-encodes a data structure.
 +
 + Translates a structure into a set of key-value pairs appropriate for use in
 + x-www-form-urlencoded POSTs and URLs. Each pair is rendered as key=value and
 + delimited by &s. All characters, except for a-z, A-Z, 0-9, and -_.~, will be
 + represented in the form %xx where xx is the hexadecimal value of each byte in
 + the character. Order is not guaranteed to be preserved.
 +
 + Standards: RFC3986
 + Params:
 +  value = The structure to encode
 +/
string urlEncode(T)(T value) if (isURLEncodable!T) {
	import std.string : format, join;
	string[] output;
	foreach (key, values; urlEncodeInternal(value))
		foreach (value; values)
			output ~= format("%s=%s", key, value);
	return output.join("&");
}
///
unittest {
	struct Beep {
		string a;
		uint b;
		uint[] c;
	}
	{
		auto result = urlEncode(Beep("treeee&", 3, [1,2,5]));
		assert((result == "a=treeee%26&b=3&c=1%2C2%2C5") || (result == "b=3&a=treeee%26&c=1%2C2%2C5") || (result == "b=3&c=1%2C2%2C5&a=treeee%26") || (result == "c=1%2C2%2C5&b=3&a=treeee%26") || (result == "c=1%2C2%2C5&a=treeee%26&b=3") || (result == "a=treeee%26&c=1%2C2%2C5&b=3"));
	}
	{
		auto result = urlEncode(["a":"treeee&", "b": "3", "c":"1,2,5"]);
		assert((result == "a=treeee%26&b=3&c=1%2C2%2C5") || (result == "b=3&a=treeee%26&c=1%2C2%2C5") || (result == "b=3&c=1%2C2%2C5&a=treeee%26") || (result == "c=1%2C2%2C5&b=3&a=treeee%26") || (result == "c=1%2C2%2C5&a=treeee%26&b=3") || (result == "a=treeee%26&c=1%2C2%2C5&b=3"));
	}
}
package string[][string] urlEncodeAssoc(in string[string] value) {
	import std.uri : encodeComponent;
	import std.string : join;
	string[][string] newData;
	foreach (key, val; value)
		newData[encodeComponent(key)] = [encodeComponent(val)];
	return newData;
}
package string[][string] urlEncodeAssoc(in string[][string] value) {
	import std.uri : encodeComponent;
	import std.string : join;
	string[][string] newData;
	foreach (key, vals; value)
		foreach (val; vals)
			newData[encodeComponent(key)] ~= encodeComponent(val);
	return newData;
}
package string[][string] urlEncodeInternal(T)(in T value) if (isURLEncodable!T) {
	import std.traits : isAssociativeArray, Unqual, ValueType;
	static if (is(T == struct))
		return urlEncodeStruct(value);
	else static if (isAssociativeArray!T) {
		static if (is(Unqual!(ValueType!T) == string))
			return urlEncodeAssoc(value);
		else static if (is(Unqual!(ValueType!T) == string[]))
			return urlEncodeAssoc(value);
	}
}

package string[][string] urlEncodeStruct(T)(in T value) if (is(T == struct)) {
	import std.traits : isSomeString, isArray, FieldNameTuple;
	import std.format : format;
	import std.conv : text;
	import std.uri : encodeComponent;
	string[][string] output;
	foreach (member; FieldNameTuple!T) {
		assert(!is(typeof(__traits(getMember, value, member)) == struct), "Cannot URL encode nested structs");
		static if (isArray!(typeof(__traits(getMember, value, member))) && !isSomeString!(typeof(__traits(getMember, value, member)))) {
			output[encodeComponent(member)] = [encodeComponent(format("%-(%s,%)", __traits(getMember, value, member)))];
		} else
			output[encodeComponent(member)] = [encodeComponent(__traits(getMember, value, member).text)];
	}
	return output;
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
	enum isURLEncodable = __traits(compiles, { T thing; urlEncodeStruct(thing); }) || __traits(compiles, { T thing; urlEncodeAssoc(thing); });
}
///
unittest {
	struct Test {
		string a;
	}
	static assert(isURLEncodable!Test);
	static assert(isURLEncodable!(string[string]));
	static assert(isURLEncodable!(string[][string]));
	static assert(!isURLEncodable!uint);
}