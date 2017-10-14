module easyhttp.fs;


version(Windows) private enum maxPath = 260;
version(Posix) private enum maxPath = 255;

alias FileSystemPath = string;
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
FileSystemPath fixPath(in FileSystemPath inPath) nothrow in {
	assert(inPath != "", "No path");
} out(result) {
	import std.path : isValidPath;
	assert(result.isValidPath(), "Invalid path from fixPath("~inPath~")");
} body {
	FileSystemPath UNCize(FileSystemPath input) pure @safe {
		import std.path : absolutePath, buildNormalizedPath;
		FileSystemPath dest = input;
		version(Windows) {
			dest = dest.absolutePath().buildNormalizedPath();
			if ((dest.length < 4) || (dest[0..4] != `\\?\`))
				dest = `\\?\` ~ dest;
		}
		return dest;
	}
	import std.algorithm : among, filter, min;
	import std.array : array;
	import std.path : absolutePath, baseName, buildNormalizedPath, dirName, extension;
	import std.string : removechars;
	import std.utf : byCodeUnit;
	FileSystemPath dest = inPath;
	try {
		version(Windows) {
			if ((dest.length >= 4) && (dest[0..4] == `\\?\`))
				dest = dest[4..$];
			dest = dest.byCodeUnit.filter!(x => !x.among!('"','?','<','>','|','*')).array;
			if ((dest.length >= 3) && (dest[1..3] == `:\`))
				dest = dest[0..3]~dest[3..$].byCodeUnit.filter!(x => x != ':').array;
			else
				dest = dest.byCodeUnit.filter!(x => x != ':').array;
		}
		if (dest[$-1] == '.')
			dest ~= "tmp";
		if (dest.absolutePath().length > maxPath)
			dest = (dest.dirName() ~ "/" ~ dest.baseName()[0..min($,(maxPath-10)-(dest.absolutePath().dirName() ~ "/" ~ dest.absolutePath().extension()).length)] ~ dest.extension()).buildNormalizedPath();
		dest = UNCize(dest);
		return dest.idup;
	} catch (Exception) {
		return inPath;
	}
}
unittest {
	string[] pathsToTest = ["yes", "loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong", "invalid&", `\\?\C:\windows\system32`];
	foreach (path; pathsToTest)
		fixPath(path);
	version(Windows) assert(fixPath(`\\?\C:\windows`) == `\\?\C:\windows`);
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
string duplicateName(string oldFilename) {
	import std.string : format;
	import std.format : formattedRead;
	import std.path : stripExtension, extension;
	string dupePrefix;
	uint dupeid;
	try {
		auto noext = stripExtension(oldFilename);
		formattedRead(noext, "%s(%s)", &dupePrefix, &dupeid);
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