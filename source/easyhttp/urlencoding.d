module easyhttp.urlencoding;

import std.algorithm;
import std.array;
import std.conv;
import std.exception;
import std.format;
import std.range;
import std.string;
import std.traits;
import std.uri;
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
auto urlEncode(T)(T value) if (isURLEncodable!T) {
	import requests : QueryParam;
	QueryParam[] output;
	foreach (key, values; urlEncodeInternal!(T, false)(value))
		foreach (value; values)
			output ~= QueryParam(key, value);
	return output;
}
///
@safe pure unittest {
	import requests : QueryParam;
	struct Beep {
		string a;
		uint b;
		uint[] c;
	}
	{
		auto result = sort(urlEncode(Beep("treeee&", 3, [1,2,5])));
		assert(result.array == [QueryParam("a", "treeee&"),QueryParam("b", "3"),QueryParam("c", "1,2,5")]);
	}
	{
		auto result = sort(urlEncode(["a":"treeee&", "b": "3", "c":"1,2,5"]));
		assert(result.array == [QueryParam("a", "treeee&"),QueryParam("b", "3"),QueryParam("c", "1,2,5")]);
	}
	{
		const(string)[string] constTest = ["a":"treeee&", "b": "3", "c":"1,2,5"];
		auto result = sort(urlEncode(constTest));
		assert(result.array == [QueryParam("a", "treeee&"),QueryParam("b", "3"),QueryParam("c", "1,2,5")]);
	}
	{
		immutable(string)[string] immutableTest = ["a":"treeee&", "b": "3", "c":"1,2,5"];
		auto result = sort(urlEncode(immutableTest));
		assert(result.array == [QueryParam("a", "treeee&"),QueryParam("b", "3"),QueryParam("c", "1,2,5")]);
	}
	{
		const(string)[][string] constTest = ["a":["treeee&"], "b": ["3"], "c":["1,2,5"]];
		auto result = sort(urlEncode(constTest));
		assert(result.array == [QueryParam("a", "treeee&"),QueryParam("b", "3"),QueryParam("c", "1,2,5")]);
	}
	{
		immutable(string)[][string] immutableTest = ["a":["treeee&"], "b": ["3"], "c":["1,2,5"]];
		auto result = sort(urlEncode(immutableTest));
		assert(result.array == [QueryParam("a", "treeee&"),QueryParam("b", "3"),QueryParam("c", "1,2,5")]);
		//assert(result.array == [QueryParam("a", "treeee%26"),QueryParam("b", "3"),QueryParam("c", "1%2C2%2C5")]);
	}
}
auto urlEncoded(T)(T value) if (isURLEncodable!T) {
	import requests : QueryParam;
	QueryParam[] output;
	foreach (key, values; urlEncodeInternal!(T, true)(value))
		foreach (value; values)
			output ~= QueryParam(key, value);
	return output;
}
///
@safe pure unittest {
	import requests : QueryParam;
	struct Beep {
		string a;
		uint b;
		uint[] c;
	}
	{
		auto result = sort(urlEncoded(Beep("treeee&", 3, [1,2,5])));
		assert(result.array == [QueryParam("a", "treeee%26"),QueryParam("b", "3"),QueryParam("c", "1%2C2%2C5")]);
	}
	{
		auto result = sort(urlEncoded(["a":"treeee&", "b": "3", "c":"1,2,5"]));
		assert(result.array == [QueryParam("a", "treeee%26"),QueryParam("b", "3"),QueryParam("c", "1%2C2%2C5")]);
	}
	{
		const(string)[string] constTest = ["a":"treeee&", "b": "3", "c":"1,2,5"];
		auto result = sort(urlEncoded(constTest));
		assert(result.array == [QueryParam("a", "treeee%26"),QueryParam("b", "3"),QueryParam("c", "1%2C2%2C5")]);
	}
	{
		immutable(string)[string] immutableTest = ["a":"treeee&", "b": "3", "c":"1,2,5"];
		auto result = sort(urlEncoded(immutableTest));
		assert(result.array == [QueryParam("a", "treeee%26"),QueryParam("b", "3"),QueryParam("c", "1%2C2%2C5")]);
	}
	{
		const(string)[][string] constTest = ["a":["treeee&"], "b": ["3"], "c":["1,2,5"]];
		auto result = sort(urlEncoded(constTest));
		assert(result.array == [QueryParam("a", "treeee%26"),QueryParam("b", "3"),QueryParam("c", "1%2C2%2C5")]);
	}
	{
		immutable(string)[][string] immutableTest = ["a":["treeee&"], "b": ["3"], "c":["1,2,5"]];
		auto result = sort(urlEncoded(immutableTest));
		assert(result.array == [QueryParam("a", "treeee%26"),QueryParam("b", "3"),QueryParam("c", "1%2C2%2C5")]);
	}
}
package string encodeComponentSafe(string input) @safe pure {
	string output;
	output.reserve(input.length*3);
	foreach (character; input) {
		if ((character >= 'a') && (character <= 'z') || (character >= 'A') && (character <= 'Z') || (character >= '0') && (character <= '9') || character.among('-', '_', '.', '!', '~', '*', '\'', '(', ')')) {
			output ~= character;
		} else {
			output ~= format!"%%%02X"(character);
		}
	}
	return output;
}
///
@safe pure unittest {
	assert(encodeComponentSafe("Hello") == "Hello");
	assert(encodeComponentSafe("Hello ") == "Hello%20");
	assert(encodeComponentSafe("Helloã") == "Hello%C3%A3");
}
package string decodeComponentSafe(string input) @safe pure {
	import std.utf : byCodeUnit;
	string output;
	output.reserve(input.length);
	ubyte decodingState;
	ubyte decodingChar;
	foreach (character; input.byCodeUnit) {
		if (character == '%') {
			decodingState = 2;
			decodingChar = 0;
		} else if (decodingState > 0) {
			decodingChar |= [character].to!ubyte(16) << ((decodingState-1)*4);
			decodingState--;
			if (decodingState == 0) {
				output ~= cast(char)decodingChar;
			}
		} else {
			output ~= character;
		}
	}
	return output;
}
///
@safe pure unittest {
	assert(decodeComponentSafe("Hello") == "Hello");
	assert(decodeComponentSafe("Hello%20") == "Hello ");
	assert(decodeComponentSafe("Hello%C3%A3") == "Helloã");
	assert(decodeComponentSafe("Hello%") == "Hello");
	assert(decodeComponentSafe("Hello%1") == "Hello");
}
package string[][string] urlEncodeAssoc(bool performEncoding = true)(in string[][string] value) @safe pure {
	string[][string] newData;
	foreach (key, vals; value) {
		foreach (val; vals) {
			static if (performEncoding) {
				newData[encodeComponentSafe(key)] ~= [encodeComponentSafe(val)];
			} else {
				newData[key] ~= [val];
			}
		}
	}
	return newData;
}
package string[][string] toURLParams(in string[string] value) @safe pure nothrow {
	string[][string] newData;
	try {
		foreach (key, val; value)
			newData[key] = [val];
	} catch(Exception) {
		assert(0, "Associative array iteration threw somehow");
	}
	return newData;
}
package string[][string] toURLParams(string[][string] value) @safe pure nothrow {
	return value;
}
package string[][string] toURLParams(in string[][string] value) @safe pure nothrow {
	string[][string] output;
	try {
		foreach (k, v; value)
			output[k] = v.dup;
	} catch(Exception) {
		assert(0, "Associative array iteration threw somehow");
	}
	return output;
}
package string[][string] urlEncodeInternal(T, bool urlEncode = true)(in T value) if (isURLEncodable!T) {
	static if (is(T == struct))
		return urlEncodeAssoc!urlEncode(toURLParams(value));
	else static if (isAssociativeArray!T) {
		static if (is(Unqual!(ValueType!T) == string)
			|| (isArray!(Unqual!(ValueType!T)) && is(Unqual!(ElementType!(Unqual!(ValueType!T))) == string)))
			return urlEncodeAssoc!urlEncode(toURLParams(value));
	}
}
package string[][string] toURLParams(T)(in T value) if (is(T == struct)) {
	string[][string] output;
	foreach (member; FieldNameTuple!T) {
		assert(!is(typeof(__traits(getMember, value, member)) == struct), "Cannot URL encode nested structs");
		static if (isArray!(typeof(__traits(getMember, value, member))) && !isSomeString!(typeof(__traits(getMember, value, member)))) {
			output[member] = [format!"%-(%s,%)"(__traits(getMember, value, member))];
		} else
			output[member] = [__traits(getMember, value, member).text];
	}
	return output;
}
@safe pure unittest {
	struct Something {
		string a;
		uint b;
		bool[] c;
	}
	assert(Something("test", 3, [true, false, true]).toURLParams == ["a": ["test"], "b": ["3"], "c": ["true,false,true"]]);
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
	enum isURLEncodable = __traits(compiles, { T thing; urlEncodeAssoc(toURLParams(thing)); });
}
///
@safe pure nothrow @nogc unittest {
	struct Test {
		string a;
	}
	static assert(isURLEncodable!Test);
	static assert(isURLEncodable!(string[string]));
	static assert(isURLEncodable!(string[][string]));
	static assert(isURLEncodable!(const(string)[][string]));
	static assert(!isURLEncodable!uint);
}