module easyhttp.url;

alias URLParameters = string[][string];

alias URLHeaders = string[string];
alias URLString = string;
enum Proto { Unknown, HTTP, HTTPS, FTP, Same, None }
private alias ProtoEnum = Proto;

import std.stdio;
/++
 + Determines the protocol for the given URL.
 +
 + Supports HTTP, HTTPS, FTP, and URLs beginning with //.
 +
 + Params:
 +  url = URL to analyze
 +/
Proto urlProtocol(in string url) @property pure @safe {
	import std.string : toLower;
	import std.algorithm : startsWith;
	if (url.startsWith!"toLower(a) == b"("http:"))
		return Proto.HTTP;
	else if (url.startsWith!"toLower(a) == b"("https:"))
		return Proto.HTTPS;
	else if (url.startsWith!"toLower(a) == b"("ftp:"))
		return Proto.FTP;
	else if (url.startsWith("//"))
		return Proto.Same;
	else if (url.startsWith("/"))
		return Proto.None;
	else if (url.startsWith("."))
		return Proto.None;
	return Proto.Unknown;
}
///
unittest {
	assert("//example".urlProtocol == Proto.Same);
	assert("/example".urlProtocol == Proto.None);
	assert("http://example".urlProtocol == Proto.HTTP);
	assert("https://example".urlProtocol == Proto.HTTPS);
	assert("ftp://example".urlProtocol == Proto.FTP);
	assert("HTTP://example".urlProtocol == Proto.HTTP);
	assert("HTTPS://example".urlProtocol == Proto.HTTPS);
	assert("FTP://example".urlProtocol == Proto.FTP);
}
/++
 + Gets the hostname for the given protocol.
 +
 + Returns: hostname or empty string if none exists
 +/
string getHostname(in string URL, in Proto protocol) pure @safe {
	import std.string : toLower, split;
	auto splitComponents = URL.split("/");
	if (protocol == Proto.Unknown)
		return splitComponents[0].toLower();
	else if (protocol != Proto.None)
		return splitComponents[2].toLower();
	return "";
}
///
unittest {
	assert(getHostname("http://example/some/path", Proto.HTTP) == "example");
	assert(getHostname("https://example/some/path", Proto.HTTPS) == "example");
	assert(getHostname("ftp://example/some/path", Proto.FTP) == "example");
	assert(getHostname("wheeeeeeeeeeeeeeeeeeee", Proto.None) == "");
	assert(getHostname("example/some/path", Proto.Unknown) == "example");
}
/++
 + A Uniform Resource Locator.
 +/
struct URL {
	import easyhttp.urlencoding : isURLEncodable, urlEncodeInternal;
	alias Proto = ProtoEnum;
	///Parameters
	URLParameters params;
	///Protocol, such as HTTP or FTP
	Proto protocol;
	///Server address
	string hostname;
	///Address for some resource on the server
	string path;
	/++
	 + Constructor that allows for parameters to be constructed from any
	 + encodable struct. Order is not guaranteed to be preserved.
	 +/
	this(T)(Proto inProtocol, string inHostname, string inPath, T inParams) if (isURLEncodable!T) {
		import std.uri : decodeComponent;
		this(inProtocol, inHostname, inPath);
		foreach (key, values; urlEncodeInternal(inParams))
			foreach (value; values)
				this.params[decodeComponent(key)] ~= decodeComponent(value);
	}
	/++
	 + Basic constructor with no parameters.
	 +/
	this(Proto inProtocol, string inHostname, string inPath) {
		this.protocol = inProtocol;
		this.hostname = inHostname;
		this.path = inPath;
	}
	/++
	 + Constructor for URL strings
	 +/
	this(T)(URLString str, T inParams) if (isURLEncodable!T) {
		import std.uri : decodeComponent;
		this(str);
		foreach (key, values; urlEncodeInternal(inParams)) {
			this.params[decodeComponent(key)] = [];
			foreach (value; values)
				this.params[decodeComponent(key)] ~= decodeComponent(value);
		}
	}
	///ditto
	this(URLString str) @safe {
		import std.array : replace;
		import std.algorithm : find;
		import std.string : toLower, split, join;
		import std.uri : decode;
		this.protocol = str.urlProtocol;
		auto splitComponents = str.split("/");
		if (splitComponents.length > 0) {
			this.hostname = getHostname(str, this.protocol);
			//Get Path
			if (this.protocol == Proto.Unknown)
				this.path = splitComponents[0..$].join("/");
			else if (this.protocol == Proto.None)
				this.path = splitComponents[0..$].join("/");
			else
				this.path = splitComponents[3..$].join("/");

			auto existingParameters = this.path.find("?");
			if (existingParameters.length > 0) {
				foreach (arg; existingParameters[1..$].split("&")) {
					auto splitArg = arg.split("=");
					() @trusted {
						if (splitArg.length > 1)
							this.params[decode(splitArg[0].replace("+", " "))] = [decode(splitArg[1].replace("+", " "))];
						else
							this.params[decode(arg.replace("+", " "))] = [""];
					}();
				}
				this.path = this.path.split("?")[0];
			}
		}
	}
	/++
	 + The filename for the URL, with nothing else.
	 +/
	@property string fileName() nothrow const pure @safe {
		import std.string : split;
		if (path.split("/").length == 0)
			return "";
		return path.split("/")[$-1];
	}
	/++
	 + Returns a new URL with the set of parameters specified.
	 +/
	URL withParams(T)(T inParams) if (isURLEncodable!T) {
		return URL(protocol, hostname, path, inParams);
	}
	/++
	 + Transforms the parameters for this URL to a URL-encoded string.
	 +/
	string paramString() @property nothrow const @trusted {
		import std.uri : encode;
		import std.string : format, join, replace;
		if (params == null) return "";
		string[] parameterPrintable;
		try {
			foreach (parameter, value; params)
				foreach (subvalue; value) {
					if (subvalue == "")
						parameterPrintable ~= parameter.encode().replace(":", "%3A");
					else
						parameterPrintable ~= format("%s=%s", parameter.encode().replace(":", "%3A"), subvalue.encode().replace(":", "%3A"));
				}
		} catch (Exception e) {
			return "";
		}
		return "?"~parameterPrintable.join("&");
	}
	/++
	 + Transforms the specified relative URL to an absolute one.
	 +
	 + Params:
	 +  urlB = URL to transform
	 +/
	URL absoluteURL(in URL urlB) const {
		import std.string : split, join;
		import std.conv : to;
		Proto ProtoCopy = protocol;
		Proto ProtoCopyB = urlB.protocol;
		auto HostnameCopy = hostname.idup;
		auto PathCopy = path.idup;
		auto ParamsCopy = params.to!URLParameters;
		if (urlB.toString() == "")
			return URL(ProtoCopy, HostnameCopy, PathCopy, ParamsCopy);
		if (this == urlB)
			return URL(ProtoCopy, HostnameCopy, PathCopy, ParamsCopy);
		if ((urlB.protocol == Proto.HTTP) || (urlB.protocol == Proto.HTTPS))
			return URL(ProtoCopyB, urlB.hostname.idup, urlB.path.idup, urlB.params.to!URLParameters);
		if ((urlB.protocol == Proto.None) && (urlB.path == "."))
			return URL(ProtoCopy, HostnameCopy, PathCopy, ParamsCopy);
		if ((urlB.protocol == Proto.None) && (urlB.path == ".."))
			return URL(ProtoCopy, HostnameCopy, PathCopy.split("/")[0..$-1].join("/"), ParamsCopy);
		if (urlB.protocol == Proto.None)
			return URL(ProtoCopy, HostnameCopy, urlB.path.idup, urlB.params.to!URLParameters);
		if (urlB.protocol == Proto.Same)
			return URL(ProtoCopy, urlB.hostname, urlB.path.idup, urlB.params.to!URLParameters);
		return URL(ProtoCopy, HostnameCopy, PathCopy ~ "/" ~ urlB.path, ParamsCopy);
	}
	///ditto
	URL absoluteURL(string urlB) const {
		return absoluteURL(URL(urlB));
	}
	///ditto
	URL absoluteURL(T)(string urlB, T params) const if (isURLEncodable!T) {
		return absoluteURL(URL(urlB, params));
	}
	/++
	 + Returns URL as a string.
	 +/
	string toString(bool includeParameters) const @safe {
		string output;
		if (protocol == Proto.HTTPS)
			output ~= "https://" ~ hostname;
		else if (protocol == Proto.HTTP)
			output ~= "http://" ~ hostname;
		else if ((protocol == Proto.None) && (hostname != hostname.init))
			throw new Exception("Invalid URL State");
		else if (protocol == Proto.Same)
			output ~= "//" ~ hostname;
		if ((output.length > 0) && (output[$-1] != '/') && (path != path.init) && (path[0] != '/'))
			output ~= "/";
		output ~= path;
		if (includeParameters) {
			if (paramString() != "") {
				if (path == path.init)
					output ~= "/";
				output ~= paramString();
			}
		}
		return output;
	}
	///ditto
	string toString() const @safe {
		return toString(true);
	}
}
unittest {
	assert(URL("http://url.example/?a=b").toString() == "http://url.example/?a=b", "Simple complete URL failure");
	assert(URL("https://url.example/?a=b").toString() == "https://url.example/?a=b", "Simple complete URL (https) failure");
	assert(URL("http://url.example").toString() == "http://url.example", "Simple complete URL (no ending slash) failure");
	assert(URL("something").toString() == "something", "Path-only relative URL recreation failure");
	assert(URL("/something").toString() == "/something", "Path-only absolute URL recreation failure");
}
unittest {
	struct Test {
		string a;
	}
	assert(URL("http://url.example/", ["a":"b"]).toString() == "http://url.example/?a=b", "Simple complete URL + assoc param failure");
	assert(URL("http://url.example/", ["a":["b"]]).toString() == "http://url.example/?a=b", "Simple complete URL + assoc arr param failure");
	assert(URL("http://url.example/", Test("b")).toString() == "http://url.example/?a=b", "Simple complete URL + struct param failure");
	assert(URL("http://url.example/?a=c", ["a":"b"]).toString() == "http://url.example/?a=b", "Simple complete URL + assoc param override failure");
}
unittest {
	assert(URL("http://url.example").protocol == Proto.HTTP, "HTTP detection failure");
	assert(URL("https://url.example").protocol == Proto.HTTPS, "HTTPS detection failure");
	assert(URL("url.example").protocol == Proto.Unknown, "No-protocol detection failure");
	assert(URL("HTTP://URL.EXAMPLE").protocol == Proto.HTTP, "HTTP caps detection failure");
	assert(URL("HTTPS://URL.EXAMPLE").protocol == Proto.HTTPS, "HTTPS caps detection failure");
	assert(URL("URL.EXAMPLE").protocol == Proto.Unknown, "No-protocol caps detection failure");
}
unittest {
	assert(URL("http://url.example").hostname == "url.example", "HTTP hostname detection failure");
	assert(URL("https://url.example").hostname == "url.example", "HTTPS hostname detection failure");
	assert(URL("url.example").hostname == "url.example", "No-protocol hostname detection failure");
	assert(URL("http://url.example/dir").hostname == "url.example", "HTTP hostname detection failure");
	assert(URL("HTTP://URL.EXAMPLE").hostname == "url.example", "HTTP caps hostname detection failure");
	assert(URL("HTTPS://URL.EXAMPLE").hostname == "url.example", "HTTPS caps hostname detection failure");
	assert(URL("URL.EXAMPLE").hostname == "url.example", "No-protocol caps hostname detection failure");
	assert(URL("http://URL.EXAMPLE/DIR").hostname == "url.example", "path+caps hostname detection failure");
}
unittest {
	assert(URL("http://url.example").absoluteURL("https://url.example").toString() == "https://url.example", "Switching protocol (string) failure");
	assert(URL("http://url.example").absoluteURL(URL("https://url.example")).toString() == "https://url.example", "Switching protocol (struct) failure");
	assert(URL("http://url.example").absoluteURL("http://url.example").toString() == "http://url.example", "Identical URL (string) failure");
	assert(URL("http://url.example").absoluteURL(URL("http://url.example")).toString() == "http://url.example", "Identical URL (struct) failure");
	assert(URL("http://url.example").absoluteURL("/something").toString() == "http://url.example/something", "Root-relative URL (string) failure");
	assert(URL("http://url.example").absoluteURL(URL("/something")).toString() == "http://url.example/something", "Root-relative URL (struct) failure");
	assert(URL("http://url.example").absoluteURL("//different.example").toString() == "http://different.example", "Same-protocol relative URL (string) failure");
	assert(URL("http://url.example").absoluteURL(URL("//different.example")).toString() == "http://different.example", "Same-protocol relative URL (struct) failure");
	assert(URL("http://url.example/dir").absoluteURL(".").toString() == "http://url.example/dir", "Dot URL (string) failure");
	assert(URL("http://url.example/dir").absoluteURL(URL(".")).toString() == "http://url.example/dir", "Dot URL (struct) failure");
	assert(URL("http://url.example/dir").absoluteURL("..").toString() == "http://url.example", "Relative parent URL (string) failure");
	assert(URL("http://url.example/dir").absoluteURL(URL("..")).toString() == "http://url.example", "Relative parent URL (struct) failure");
	assert(URL("http://url.example/dir").absoluteURL("/different").toString() == "http://url.example/different", "Root-relative (w/dir) URL (string) failure");
	assert(URL("http://url.example/dir").absoluteURL(URL("/different")).toString() == "http://url.example/different", "Root-relative (w/dir) URL (struct) failure");
	assert(URL("http://url.example/dir").absoluteURL("different").toString() == "http://url.example/dir/different", "cwd-relative (w/dir) URL (string) failure");
	assert(URL("http://url.example/dir").absoluteURL(URL("different")).toString() == "http://url.example/dir/different", "cwd-relative (w/dir) URL (struct) failure");
}
unittest {
	assert(URL("").params is null, "URIArguments: Empty string failure");
	assert(URL("http://url.example/?hello=world").params == ["hello":["world"]], "URIArguments: Simple test failure");
	assert(URL("http://url.example/?hello=world+butt").params == ["hello":["world butt"]], "URIArguments: Plus as space in value failure");
	assert(URL("http://url.example/?hello+butt=world").params == ["hello butt":["world"]], "URIArguments: Plus as space in key failure");
	assert(URL("http://url.example/?hello=world%20butt").params == ["hello":["world butt"]], "URIArguments: URL decoding in value failure");
	assert(URL("http://url.example/?hello%20butt=world").params == ["hello butt":["world"]], "URIArguments: URL decoding in key failure");
	assert(URL("http://url.example/?hello").params == ["hello":[""]], "URIArguments: Key only failure");
	assert(URL("http://url.example/?hello=").params == ["hello":[""]], "URIArguments: Empty value failure");
	assert(URL("http://url.example/?hello+").params == ["hello ":[""]], "URIArguments: Key only with plus sign failure");
	assert(URL("http://url.example/?hello+=").params == ["hello ":[""]], "URIArguments: Empty value with plus sign failure");
}
unittest {
	assert(URL("http://url.example/?test", ["test2": ["value"]]).params == ["test":[""], "test2":["value"]], "Merged parameters failure");
}