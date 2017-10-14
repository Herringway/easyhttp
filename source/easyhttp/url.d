module easyhttp.url;

alias URLHeaders = string[string];

import std.algorithm;
import std.array;
import std.conv;
import std.exception;
import std.format;
import std.range;
import std.string;
import std.uni;
import std.uri;

import easyhttp.urlencoding;

/++
 + Determines the protocol for the given URL.
 +
 + Supports HTTP, HTTPS, FTP, and URLs beginning with //.
 +
 + Params:
 +  url = URL to analyze
 +/
URL.Proto urlProtocol(in string url) pure @safe nothrow {
	if (assumeWontThrow(url.startsWith!"toLower(a) == b"("http:")))
		return URL.Proto.HTTP;
	else if (assumeWontThrow(url.startsWith!"toLower(a) == b"("https:")))
		return URL.Proto.HTTPS;
	else if (assumeWontThrow(url.startsWith!"toLower(a) == b"("ftp:")))
		return URL.Proto.FTP;
	else if (url.startsWith("//"))
		return URL.Proto.Same;
	else if (url.startsWith("/"))
		return URL.Proto.None;
	else if (url.startsWith("."))
		return URL.Proto.None;
	return URL.Proto.Unknown;
}
///
@safe pure nothrow unittest {
	assert("//example".urlProtocol == URL.Proto.Same);
	assert("/example".urlProtocol == URL.Proto.None);
	assert("http://example".urlProtocol == URL.Proto.HTTP);
	assert("https://example".urlProtocol == URL.Proto.HTTPS);
	assert("ftp://example".urlProtocol == URL.Proto.FTP);
	assert("HTTP://example".urlProtocol == URL.Proto.HTTP);
	assert("HTTPS://example".urlProtocol == URL.Proto.HTTPS);
	assert("FTP://example".urlProtocol == URL.Proto.FTP);
	assert("http:example".urlProtocol == URL.Proto.HTTP);
}
/++
 + Gets the hostname for the given protocol.
 +
 + Returns: hostname or empty string if none exists
 +/
string getHostname(in string url, in URL.Proto protocol) pure @safe nothrow {
	auto splitComponents = url.split(":");
	if (protocol == URL.Proto.None)
		return "";
	if (!protocol.among(URL.Proto.Unknown, URL.Proto.Same))
		splitComponents = splitComponents.drop(1);
	auto domain = splitComponents.join(":").split("/").filter!(x => !x.empty);
	if (domain.empty)
		return "";
	return assumeWontThrow(domain.front.toLower());
}
///
@safe pure nothrow unittest {
	assert(getHostname("http://example/some/path", URL.Proto.HTTP) == "example");
	assert(getHostname("https://example/some/path", URL.Proto.HTTPS) == "example");
	assert(getHostname("ftp://example/some/path", URL.Proto.FTP) == "example");
	assert(getHostname("//example/some/path", URL.Proto.Same) == "example");
	assert(getHostname("wheeeeeeeeeeeeeeeeeeee", URL.Proto.None) == "");
	assert(getHostname("example/some/path", URL.Proto.Unknown) == "example");
	assert(getHostname("http:example", URL.Proto.HTTP) == "example");
}
/++
 + A Uniform Resource Locator.
 +/
struct URL {
	enum Proto { Unknown, HTTP, HTTPS, FTP, Same, None }
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
		this(inProtocol, inHostname, inPath);
		this.params = inParams.toURLParams();
	}
	/++
	 + Basic constructor with no parameters.
	 +/
	this(Proto inProtocol, string inHostname, string inPath = "/") pure @safe nothrow @nogc {
		this.protocol = inProtocol;
		this.hostname = inHostname;
		this.path = inPath;
	}
	/++
	 + Constructor for URL strings
	 +/
	this(T)(string str, T inParams) if (isURLEncodable!T) {
		this(str);
		foreach (key, values; urlEncodeInternal(inParams)) {
			this.params[decodeComponentSafe(key)] = [];
			foreach (value; values)
				this.params[decodeComponentSafe(key)] ~= decodeComponentSafe(value);
		}
	}
	///ditto
	this(string str, Flag!"SemicolonQueryParameters" semicolonQueryParameters = Flag!"SemicolonQueryParameters".no) @safe pure nothrow {
		import std.utf : byCodeUnit;
		this.protocol = str.urlProtocol;
		auto splitComponents = str.split("/");
		if (splitComponents.length > 0) {
			this.hostname = getHostname(str, this.protocol);
			//Get Path
			if (this.protocol.among(Proto.Unknown, Proto.None))
				this.path = splitComponents.join("/");
			else
				this.path = splitComponents.drop(3).join("/");
			auto existingParameters = this.path.find("?");
			if (existingParameters.length > 0) {
				foreach (arg; existingParameters[1..$].byCodeUnit.splitter!(x => x == (semicolonQueryParameters ? ';' : '&'))) {
					auto splitArg = arg.splitter("=");
					if (splitArg.empty) {
						continue;
					}
					string key = "";
					string value = "";
					try {
						key = decodeComponentSafe(splitArg.front.array.replace("+", " "));
						splitArg.popFront();
						if (!splitArg.empty) {
							value = decodeComponentSafe(splitArg.front.array.replace("+", " "));
						}
					} catch (Exception) {
						assert(0, "Invalid char decoded");
					}
					this.params[key] ~= value;
				}
				this.path = this.path.split("?")[0];
			}
		}
	}
	/++
	 + The filename for the URL, with nothing else.
	 +/
	string fileName() nothrow const pure @safe {
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
	string paramString() nothrow const @trusted pure {
		if (params.empty) return "";
		string[] parameterPrintable;
		try {
			foreach (parameter, value; params)
				foreach (subvalue; value) {
					if (subvalue == "")
						parameterPrintable ~= parameter.encodeComponentSafe().replace(":", "%3A").replace("+", "%2B");
					else
						parameterPrintable ~= format("%s=%s", parameter.encodeComponentSafe().replace(":", "%3A").replace("+", "%2B"), subvalue.encodeComponentSafe().replace(":", "%3A").replace("+", "%2B"));
				}
		} catch (Exception e) {
			return "";
		}
		return parameterPrintable.sort().join("&");
	}
	/++
	 + Transforms the specified relative URL to an absolute one.
	 +
	 + Params:
	 +  urlB = URL to transform
	 +/
	URL absoluteURL(in URL urlB) const @safe pure nothrow {
		Proto ProtoCopy = protocol;
		Proto ProtoCopyB = urlB.protocol;
		immutable HostnameCopy = hostname;
		immutable PathCopy = path;
		const ParamsCopy = params;
		immutable HostnameCopyB = urlB.hostname;
		immutable PathCopyB = urlB.path;
		const ParamsCopyB = urlB.params;
		if (urlB == const(URL).init)
			return URL(ProtoCopy, HostnameCopy, PathCopy, ParamsCopy);
		if (this == urlB)
			return URL(ProtoCopy, HostnameCopy, PathCopy, ParamsCopy);
		if ((urlB.protocol == Proto.HTTP) || (urlB.protocol == Proto.HTTPS))
			return URL(ProtoCopyB, HostnameCopyB, PathCopyB, ParamsCopyB);
		if ((urlB.protocol == Proto.None) && (urlB.path == "."))
			return URL(ProtoCopy, HostnameCopy, PathCopy, ParamsCopy);
		if ((urlB.protocol == Proto.None) && (urlB.path == ".."))
			return URL(ProtoCopy, HostnameCopy, PathCopy.split("/")[0..$-1].join("/"), ParamsCopy);
		if (urlB.protocol == Proto.None)
			return URL(ProtoCopy, HostnameCopy, PathCopyB, ParamsCopyB);
		if (urlB.protocol == Proto.Same)
			return URL(ProtoCopy, urlB.hostname, PathCopyB, ParamsCopyB);
		return URL(ProtoCopy, HostnameCopy, PathCopy ~ "/" ~ urlB.path, ParamsCopy);
	}
	///ditto
	URL absoluteURL(string urlB) const pure @safe nothrow {
		return absoluteURL(URL(urlB));
	}
	///ditto
	URL absoluteURL(T)(string urlB, T params) const if (isURLEncodable!T) {
		return absoluteURL(URL(urlB, params));
	}
	/++
	 + Returns URL as a string.
	 +/
	string toString(bool includeParameters) const @safe pure {
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
				output ~= "?"~paramString();
			}
		}
		return output;
	}
	void toString(T)(T sink, FormatSpec!char fmt = FormatSpec!char.init) const if (isOutputRange!(T, char[])) {
		if (protocol == Proto.HTTPS) {
			sink("https://");
		} else if (protocol == Proto.HTTP) {
			sink("http://");
		} else if ((protocol == Proto.None) && (hostname != hostname.init)) {
			throw new Exception("Invalid URL State");
		} else if (protocol == Proto.Same) {
			sink("//");
		}

		sink(hostname);

		if ((hostname.length > 0) && !hostname.endsWith('/') && (path != path.init) && (path[0] != '/'))
			sink("/");

		sink(path);

		switch (fmt.spec) {
			case 's':
				if (paramString() != "") {
					if (path == path.init)
						sink("/");
					sink("?");
					sink(paramString());
				}
				break;
			case 'n': break;
			default: assert(0, "Invalid format spec");
		}
	}
	///ditto
	string toString() const @safe pure {
		return toString(true);
	}
}
@safe pure unittest {
	const a = URL(URL.Proto.HTTP, "localhost", "/", ["a": "b"]);
	const b = URL(URL.Proto.HTTP, "localhost", "/");
}
@safe pure unittest {
	assert(URL("http://url.example/?a=b").toString() == "http://url.example/?a=b", "Simple complete URL failure");
	assert(URL("https://url.example/?a=b").toString() == "https://url.example/?a=b", "Simple complete URL (https) failure");
	assert(URL("http://url.example").toString() == "http://url.example", "Simple complete URL (no ending slash) failure");
	assert(URL("something").toString() == "something", "Path-only relative URL recreation failure");
	assert(URL("/something").toString() == "/something", "Path-only absolute URL recreation failure");
	assert(URL("/something?a=b:d").toString() == "/something?a=b%3Ad");
	assert(URL("http://url.example/?a=b&&").toString() == "http://url.example/?a=b");
	assert(URL("http://url.example/?a=b;;", Flag!"SemicolonQueryParameters".yes).toString() == "http://url.example/?a=b");
}
@safe pure unittest {
	struct Test {
		string a;
	}
	assert(URL("http://url.example/", ["a":"b"]).toString() == "http://url.example/?a=b", "Simple complete URL + assoc param failure");
	assert(URL("http://url.example/", ["a":["b"]]).toString() == "http://url.example/?a=b", "Simple complete URL + assoc arr param failure");
	assert(URL("http://url.example/", Test("b")).toString() == "http://url.example/?a=b", "Simple complete URL + struct param failure");
	assert(URL("http://url.example/?a=c", ["a":"b"]).toString() == "http://url.example/?a=b", "Simple complete URL + assoc param override failure");
}
@safe pure unittest {
	assert(URL("http://url.example").protocol == URL.Proto.HTTP, "HTTP detection failure");
	assert(URL("https://url.example").protocol == URL.Proto.HTTPS, "HTTPS detection failure");
	assert(URL("url.example").protocol == URL.Proto.Unknown, "No-protocol detection failure");
	assert(URL("HTTP://URL.EXAMPLE").protocol == URL.Proto.HTTP, "HTTP caps detection failure");
	assert(URL("HTTPS://URL.EXAMPLE").protocol == URL.Proto.HTTPS, "HTTPS caps detection failure");
	assert(URL("URL.EXAMPLE").protocol == URL.Proto.Unknown, "No-protocol caps detection failure");
	assert(URL("http:url.example").protocol == URL.Proto.HTTP);
	assert(URL("/something?a=b:d").protocol == URL.Proto.None);
}
@safe pure unittest {
	assert(URL("http://url.example").hostname == "url.example", "HTTP hostname detection failure");
	assert(URL("https://url.example").hostname == "url.example", "HTTPS hostname detection failure");
	assert(URL("url.example").hostname == "url.example", "No-protocol hostname detection failure");
	assert(URL("http://url.example/dir").hostname == "url.example", "HTTP hostname detection failure");
	assert(URL("HTTP://URL.EXAMPLE").hostname == "url.example", "HTTP caps hostname detection failure");
	assert(URL("HTTPS://URL.EXAMPLE").hostname == "url.example", "HTTPS caps hostname detection failure");
	assert(URL("URL.EXAMPLE").hostname == "url.example", "No-protocol caps hostname detection failure");
	assert(URL("http://URL.EXAMPLE/DIR").hostname == "url.example", "path+caps hostname detection failure");
	assert(URL("HTTP:url.example").hostname == "url.example");
	assert(URL("/something?a=b:d").hostname == "");
}
@safe pure unittest {
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
@safe pure unittest {
	assert(URL("").params == URL.params.init, "URIArguments: Empty string failure");
	assert(URL("http://url.example/?hello=world").params == ["hello":["world"]], "URIArguments: Simple test failure");
	assert(URL("http://url.example/?hello=world+butt").params == ["hello":["world butt"]], "URIArguments: Plus as space in value failure");
	assert(URL("http://url.example/?hello+butt=world").params == ["hello butt":["world"]], "URIArguments: Plus as space in key failure");
	assert(URL("http://url.example/?hello=world%20butt").params == ["hello":["world butt"]], "URIArguments: URL decoding in value failure");
	assert(URL("http://url.example/?hello%20butt=world").params == ["hello butt":["world"]], "URIArguments: URL decoding in key failure");
	assert(URL("http://url.example/?hello").params == ["hello":[""]], "URIArguments: Key only failure");
	assert(URL("http://url.example/?hello=").params == ["hello":[""]], "URIArguments: Empty value failure");
	assert(URL("http://url.example/?hello+").params == ["hello ":[""]], "URIArguments: Key only with plus sign failure");
	assert(URL("http://url.example/?hello+=").params == ["hello ":[""]], "URIArguments: Empty value with plus sign failure");
	assert(URL("http://url.example/?hello+=").text == "http://url.example/?hello%20");
	assert(URL("http://url.example/?hello=1&hello=2").params == ["hello":["1", "2"]], "URIArguments: Duplicate key failure");
	auto url = URL("http://url.example");
	url.params["hello"] = ["+"];
	assert(url.text == "http://url.example/?hello=%2B");
	assert(format!"%n"(URL("http://url.example/?hello")) == "http://url.example");
	assert(format!"%s"(URL("http://url.example/?hello")) == "http://url.example/?hello");
}
@safe pure unittest {
	assert(URL("http://url.example/?test", ["test2": ["value"]]).params == ["test":[""], "test2":["value"]], "Merged parameters failure");
}