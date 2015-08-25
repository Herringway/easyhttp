module httpinterface.fs;


version(Windows) int maxPath = 260;
version(Posix) int maxPath = 255;

alias FileSystemPath = string;

FileSystemPath fixPath(in FileSystemPath inPath) nothrow in {
	assert(inPath != "", "No path");
} out(result) {
	import std.path;
	assert(result.isValidPath(), "Invalid path from fixPath("~inPath~")");
} body {
	FileSystemPath UNCize(FileSystemPath input) pure @safe {
		import std.path;
		FileSystemPath dest = input;
		version(Windows) {
			dest = dest.absolutePath().buildNormalizedPath();
			if ((dest.length < 4) || (dest[0..4] != `\\?\`))
				dest = `\\?\` ~ dest;
		}
		return dest;
	}
	import std.algorithm : min;
	import std.string : removechars;
	import std.path;
	FileSystemPath dest = inPath;
	try {
		version(Windows) {
			if ((dest.length >= 4) && (dest[0..4] == `\\?\`))
				dest = dest[4..$];
			dest = dest.removechars(`"?<>|*`);
			if ((dest.length >= 3) && (dest[1..3] == `:\`))
				dest = dest[0..3]~dest[3..$].removechars(`:`);
			else
				dest = dest.removechars(`:`);
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
@property string duplicateName(string oldFilename) {
	import std.string : format;
	import std.format : formattedRead;
	import std.path : stripExtension, extension;
	string dupePrefix;
	uint dupeid;
	try {
		auto noext = stripExtension(oldFilename);
		formattedRead(noext, "%s(%s)", &dupePrefix, &dupeid);
		dupeid++;
	} catch {
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