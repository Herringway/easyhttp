module easyhttp.fs;

import std.stdio : File;
import std.datetime : SysTime;

version(Windows) {
	private enum maxPath = 32767;
	private enum softMaxPath = 260;
} else version(Posix) {
	private enum maxPath = 255;
}

enum InvalidCharHandling {
	replaceUnicode,
	remove
}

/++
 + Fixes up invalid paths.
 +
 + Removes characters from paths that are not allowed in filenames on the host
 + operating system. Filenames are also trimmed to fit the maximum path length.
 + Additionally, paths are converted to UNC format on Windows.
 +
 + Invalid characters on Windows include "?<>|*:
 +
 + Only \0 is not allowed in POSIX paths.
 +
 + Params:
 +  inPath = path that may contain errors
 +/
auto fixPath(in string inPath, InvalidCharHandling invalidCharHandling = InvalidCharHandling.remove) @safe
	in(inPath != "", "No path")
{
	import std.algorithm.iteration : map;
	import std.algorithm.searching : skipOver;
	import std.array : array;
	import std.exception : enforce;
	import std.path : absolutePath, baseName, buildNormalizedPath, buildPath, chainPath, dirName, driveName, extension, isRooted, pathSplitter, stripExtension, withExtension;
	import std.range : chain, only;
	auto UNCize(string input) {
		version(Windows) {
			return chain(input.length > softMaxPath ? `\\?\` : "", input);
		} else {
			return input;
		}
	}
	string dest = inPath;
	version(Windows) {
		dest.skipOver(`\\?\`);
	}
	dest = buildNormalizedPath(dest.absolutePath);
	auto origDrive = dest.driveName;
	auto split = dest.pathSplitter;
	split.skipOver!isRooted();
	dest = buildPath(only(origDrive).chain(split.map!(x => fixPathComponent(x, invalidCharHandling)).array));
	const long truncationAmount = dest.length - maxPath;
	if (truncationAmount > 0) {
		enforce(dest.baseName.stripExtension.length > truncationAmount, "Path too long!");
		dest = chainPath(dest.dirName(), dest.baseName.stripExtension[0 .. $ - truncationAmount].withExtension(dest.extension)).array;
	}
	return UNCize(dest);
}
@safe unittest {
	import std.algorithm.comparison : equal;
	import std.path : asAbsolutePath;
	import std.range : chain;
	import std.utf : toUTF8;
	assert(fixPath("yes").equal("yes".asAbsolutePath));
	assert(fixPath("yes/../yes").equal("yes".asAbsolutePath));
	version(Windows) {
		assert(fixPath(longFilename).equal(`\\?\`.chain(longFilename.asAbsolutePath)));
	}
	assert(fixPath(longFilename).toUTF8.length <= maxPath);
	assert(fixPath("invalid\0").equal("invalid".asAbsolutePath));
	assert(fixPath("invalid\0", InvalidCharHandling.replaceUnicode).equal("invalid␀".asAbsolutePath));
	assert(fixPath(`\\?\C:\windows\system32`).equal(`C:\windows\system32`));
	version(Windows) assert(fixPath(`\\?\C:\windows`).equal(`C:\windows`));
}
string fixPathComponent(string input, InvalidCharHandling invalidCharHandling = InvalidCharHandling.remove) @safe pure {
	import std.algorithm : all, among, filter, map, min, substitute;
	import std.meta : aliasSeqOf;
	import std.range : repeat, roundRobin;
	import std.utf : toUTF8;
	final switch (invalidCharHandling) {
		case InvalidCharHandling.replaceUnicode:
			if (input.all!(x => x == '.')) {
				return '．'.repeat(input.length).toUTF8;
			}
			return input.substitute!(aliasSeqOf!(roundRobin(invalidPathCharacters, invalidPathUnicodeReplacements))).toUTF8;
		case InvalidCharHandling.remove:
			if (input.all!(x => x == '.')) {
				version(Windows) {} else {
					if (input.length > 2) {
						return input;
					}
				}
				throw new Exception("Cannot create valid filename from all-periods filename");
			}
			return input.filter!(x => !x.among!(aliasSeqOf!invalidPathCharacters)).toUTF8;
	}
}
@safe pure unittest {
	assert(fixPathComponent("ok") == "ok");
	assert(fixPathComponent("invalid\0") == "invalid");
	assert(fixPathComponent("invalid\0", InvalidCharHandling.replaceUnicode) == "invalid␀");
	assert(fixPathComponent("...", InvalidCharHandling.replaceUnicode) == "．．．");
}
/++
 + Creates a monotonically-increasing filename.
 +
 + Files without duplicate counts will have (2) added before the extension. If
 + the count exists, it will be incremented.
 +
 + Params:
 +  oldFilename = original filename to add/increase duplicate count for
 +/
string duplicateName(string oldFilename) @safe {
	import std.string : format;
	import std.format : formattedRead;
	import std.path : stripExtension, extension;
	string dupePrefix;
	uint dupeid;
	try {
		auto noext = stripExtension(oldFilename);
		formattedRead(noext, "%s(%s)", dupePrefix, dupeid);
		dupeid++;
	} catch(Exception) {
		dupePrefix = stripExtension(oldFilename);
		dupeid = 2;
	}
	return format("%s(%d)%s", dupePrefix, dupeid, extension(oldFilename));
}
unittest {
	assert("hello.txt"    .duplicateName == "hello(2).txt",    "Basic duplicate filename failure");
	assert("hello"        .duplicateName == "hello(2)",        "Basic duplicate filename (no extension) failure");
	assert("hello(2).txt" .duplicateName == "hello(3).txt",    "Second duplicate filename failure");
	assert("hello(10).txt".duplicateName == "hello(11).txt",   "Double digit duplicate filename failure");
	assert("hello(11).txt".duplicateName == "hello(12).txt",   "Double digit 2 duplicate filename failure");
	assert("hello(a).txt" .duplicateName == "hello(a)(2).txt", "Non-numeric duplicate filename failure");
}

version(Windows) {
	enum invalidPathCharacters = "<>:\"|?*\0\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
	enum invalidPathUnicodeReplacements = "＜＞：＂｜？＊␀␁␂␃␄␅␆␇␈␉␊␋␌␍␎␏␐␑␒␓␔␕␖␗␘␙␚␛␜␝␞␟";
} else {
	enum invalidPathCharacters = "\0";
	enum invalidPathUnicodeReplacements = "␀";
}

import std.utf : count;
static assert(invalidPathCharacters.count == invalidPathUnicodeReplacements.count);

private enum longFilename = "loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong";

package void trustedRawWrite(ref File file, const(ubyte)[] data) @trusted {
	file.rawWrite(data);
}

package immutable(ubyte)[] trustedRead(string filename) @trusted {
	import std.exception : assumeUnique;
	import std.file : read;
	return assumeUnique(cast(ubyte[])read(filename));
}

package SysTime trustedTimeLastModified(string path) @trusted {
	import std.file : timeLastModified;
	return timeLastModified(path);
}
