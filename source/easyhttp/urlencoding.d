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


struct URLParameters {
	string[][string] params;
	auto opBinaryRight(string op : "in")(string key) {
		return key in params;
	}
	auto ref opIndex(string key) {
		return params[key];
	}
	auto opIndexAssign(void[], string key) {
		return params[key] = [];
	}
	auto opIndexAssign(string val, string key) {
		return params[key] = [val];
	}
	auto opIndexAssign(string[] vals, string key) {
		return params[key] = vals;
	}
	auto opIndexAssign(T)(T val, string key) {
		import std.conv : text;
		return params[key] = [val.text];
	}
	void opIndexOpAssign(string op)(const string val, const string key) {
		if (key !in params) {
			params[key] = [];
		}
		mixin("params[key] "~op~"= val;");
	}
	void opIndexOpAssign(string op)(const string[] val, const string key) {
		if (key !in params) {
			params[key] = [];
		}
		mixin("params[key] "~op~"= val;");
	}
	void opIndexOpAssign(string op, T)(const T val, const string key) {
		import std.conv : to;
		if (key !in params) {
			params[key] = [];
		}
		mixin("params[key] "~op~"= val.to!string;");
	}
	bool empty() const pure @nogc @safe nothrow {
		return params == null;
	}
	int opApply(scope int delegate(const string, const string[]) pure @safe dg) const pure @safe {
		int result = 0;
		foreach (k,v; params) {
			result = dg(k,v);
			if (result) {
				break;
			}
		}
		return result;
	}
	int opApply(scope int delegate(const string, ref string[]) pure @safe dg) pure @safe {
		int result = 0;
		foreach (k,v; params) {
			result = dg(k,v);
			if (result) {
				break;
			}
		}
		return result;
	}
	auto opEquals(const string[][string] v) const {
		return v == params;
	}
	auto opEquals(const URLParameters v) const {
		return v.params == params;
	}
	auto remove(const string key) {
		params.remove(key);
	}
	immutable(URLParameters) idup() const @trusted pure {
		const(string[])[string] paramsCopy = params.dup;
		return immutable URLParameters(assumeUnique(paramsCopy));
	}
}
@safe pure unittest {
	{
		auto x = URLParameters();
		x["a"] = 6;
		assert(x["a"] == ["6"]);
		x["a"] ~= 7;
		assert(x["a"] == ["6", "7"]);
		x.remove("a");
		assert(x.empty);
	}
}
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
	import easyhttp.url : QueryParameter;
	QueryParameter[] output;
	foreach (key, values; urlEncodeInternal!(T, false)(value)) {
		foreach (val; values) {
			output ~= QueryParameter(key, val);
		}
	}
	return output;
}
///
@safe pure unittest {
	import easyhttp.url : QueryParameter;
	struct Beep {
		string a;
		uint b;
		uint[] c;
	}
	{
		auto result = urlEncode(Beep("treeee&", 3, [1,2,5]));
		assert(result.canFind(QueryParameter("a", "treeee&")));
		assert(result.canFind(QueryParameter("b", "3")));
		assert(result.canFind(QueryParameter("c", "1,2,5")));
	}
	{
		auto result = urlEncode(["a":"treeee&", "b": "3", "c":"1,2,5"]);
		assert(result.canFind(QueryParameter("a", "treeee&")));
		assert(result.canFind(QueryParameter("b", "3")));
		assert(result.canFind(QueryParameter("c", "1,2,5")));
	}
	{
		const(string)[string] constTest = ["a":"treeee&", "b": "3", "c":"1,2,5"];
		auto result = urlEncode(constTest);
		assert(result.canFind(QueryParameter("a", "treeee&")));
		assert(result.canFind(QueryParameter("b", "3")));
		assert(result.canFind(QueryParameter("c", "1,2,5")));
	}
	{
		immutable(string)[string] immutableTest = ["a":"treeee&", "b": "3", "c":"1,2,5"];
		auto result = urlEncode(immutableTest);
		assert(result.canFind(QueryParameter("a", "treeee&")));
		assert(result.canFind(QueryParameter("b", "3")));
		assert(result.canFind(QueryParameter("c", "1,2,5")));
	}
	{
		const(string)[][string] constTest = ["a":["treeee&"], "b": ["3"], "c":["1,2,5"]];
		auto result = urlEncode(constTest);
		assert(result.canFind(QueryParameter("a", "treeee&")));
		assert(result.canFind(QueryParameter("b", "3")));
		assert(result.canFind(QueryParameter("c", "1,2,5")));
	}
	{
		immutable(string)[][string] immutableTest = ["a":["treeee&"], "b": ["3"], "c":["1,2,5"]];
		auto result = urlEncode(immutableTest);
		assert(result.canFind(QueryParameter("a", "treeee&")));
		assert(result.canFind(QueryParameter("b", "3")));
		assert(result.canFind(QueryParameter("c", "1,2,5")));
	}
}
auto urlEncoded(T : string[][string])(T val) {
	return urlEncoded(URLParameters(val));
}
auto urlEncoded(T)(T value) if (isURLEncodable!T) {
	import easyhttp.url : QueryParameter;
	QueryParameter[] output;
	foreach (key, values; urlEncodeInternal!(T, true)(value)) {
		foreach (val; values) {
			output ~= QueryParameter(key, val);
		}
	}
	return output;
}
///
@safe pure unittest {
	import easyhttp.url : QueryParameter;
	struct Beep {
		string a;
		uint b;
		uint[] c;
	}
	{
		auto result = urlEncoded(Beep("treeee&", 3, [1,2,5]));
		assert(result.canFind(QueryParameter("a", "treeee%26")));
		assert(result.canFind(QueryParameter("b", "3")));
		assert(result.canFind(QueryParameter("c", "1%2C2%2C5")));
	}
	{
		auto result = urlEncoded(["a":"treeee&", "b": "3", "c":"1,2,5"]);
		assert(result.canFind(QueryParameter("a", "treeee%26")));
		assert(result.canFind(QueryParameter("b", "3")));
		assert(result.canFind(QueryParameter("c", "1%2C2%2C5")));
	}
	{
		const(string)[string] constTest = ["a":"treeee&", "b": "3", "c":"1,2,5"];
		auto result = urlEncoded(constTest);
		assert(result.canFind(QueryParameter("a", "treeee%26")));
		assert(result.canFind(QueryParameter("b", "3")));
		assert(result.canFind(QueryParameter("c", "1%2C2%2C5")));
	}
	{
		immutable(string)[string] immutableTest = ["a":"treeee&", "b": "3", "c":"1,2,5"];
		auto result = urlEncoded(immutableTest);
		assert(result.canFind(QueryParameter("a", "treeee%26")));
		assert(result.canFind(QueryParameter("b", "3")));
		assert(result.canFind(QueryParameter("c", "1%2C2%2C5")));
	}
	{
		const(string)[][string] constTest = ["a":["treeee&"], "b": ["3"], "c":["1,2,5"]];
		auto result = urlEncoded(constTest);
		assert(result.canFind(QueryParameter("a", "treeee%26")));
		assert(result.canFind(QueryParameter("b", "3")));
		assert(result.canFind(QueryParameter("c", "1%2C2%2C5")));
	}
	{
		immutable(string)[][string] immutableTest = ["a":["treeee&"], "b": ["3"], "c":["1,2,5"]];
		auto result = urlEncoded(immutableTest);
		assert(result.canFind(QueryParameter("a", "treeee%26")));
		assert(result.canFind(QueryParameter("b", "3")));
		assert(result.canFind(QueryParameter("c", "1%2C2%2C5")));
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
package URLParameters urlEncodeAssoc(bool performEncoding = true)(const URLParameters value) @safe pure {
	URLParameters newData;
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
package URLParameters toURLParams(const string[string] value) @safe pure nothrow {
	URLParameters newData;
	try {
		foreach (key, val; value)
			newData[key] = [val];
	} catch(Exception) {
		assert(0, "Associative array iteration threw somehow");
	}
	return newData;
}
package URLParameters toURLParams(URLParameters value) @safe pure nothrow {
	return value;
}
package URLParameters toURLParams(const URLParameters value) @safe pure nothrow {
	URLParameters output;
	try {
		foreach (k, v; value)
			output[k] = v.dup;
	} catch(Exception) {
		assert(0, "Associative array iteration threw somehow");
	}
	return output;
}
package URLParameters toURLParams(const string[][string] params) @safe pure nothrow {
	try {
		return URLParameters(params.to!(string[][string]));
	} catch (Exception) {
		return URLParameters.init;
	}
}
package URLParameters urlEncodeInternal(T, bool urlEncode = true)(in T value) if (isURLEncodable!T) {
	static if (is(T == struct))
		return urlEncodeAssoc!urlEncode(toURLParams(value));
	else static if (isAssociativeArray!T) {
		static if (is(Unqual!(ValueType!T) == string)
			|| (isArray!(Unqual!(ValueType!T)) && is(Unqual!(ElementType!(Unqual!(ValueType!T))) == string)))
			return urlEncodeAssoc!urlEncode(toURLParams(value));
	}
}
package URLParameters toURLParams(T)(in T value) if (is(T == struct)) {
	URLParameters output;
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
@safe pure unittest {
	URLParameters p;
	assert("x" !in p);
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