module easyhttp.url;

alias URLHeaders = string[string];

import std.algorithm;
import std.array;
import std.conv;
import std.exception;
import std.format;
import std.range;
import std.string;
import std.traits;
import std.uni;
import std.uri;

import easyhttp.urlencoding;

/++
 + A key/value pair, found after the ? in a URL.
 +/
struct QueryParameter {
	string key;
	string value;
}

/++
 + Determines the protocol for the given URL.
 +
 + Supports HTTP, HTTPS, FTP, and URLs beginning with //.
 +
 + Params:
 +  url = URL to analyze
 +/
URL.Proto urlProtocol(in string url) pure @safe nothrow {
	if (auto protoSplit = url.findSplit("/")[0].findSplit(":")) {
		switch (assumeWontThrow(protoSplit[0].toLower)) {
			case "http":
				return URL.Proto.HTTP;
			case "https":
				return URL.Proto.HTTPS;
			case "ftp":
				return URL.Proto.FTP;
			case "data":
				return URL.Proto.Data;
			default:
				return URL.Proto.Unknown;
		}
	} else if (url.startsWith("//")) {
		return URL.Proto.Same;
	}
	return URL.Proto.None;
}
///
@safe pure nothrow unittest {
	assert("//example".urlProtocol == URL.Proto.Same);
	assert("/example".urlProtocol == URL.Proto.None);
	assert("http://example".urlProtocol == URL.Proto.HTTP);
	assert("https://example".urlProtocol == URL.Proto.HTTPS);
	assert("ftp://example".urlProtocol == URL.Proto.FTP);
	assert("data:,example".urlProtocol == URL.Proto.Data);
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
	enum Proto { Unknown, HTTP, HTTPS, FTP, Data, Same, None }
	///Parameters
	URLParameters params;
	///Protocol, such as HTTP or FTP
	Proto protocol;
	///Server address
	string hostname;
	///Address for some resource on the server
	string path;
	///URL fragment - typically refers to a sub-resource
	string fragment;
	private this(Proto inProtocol, string inHostname, string inPath, immutable URLParameters inParams, string inFragment) immutable pure @safe nothrow {
		this.params = inParams.idup;
		this.protocol = inProtocol;
		this.hostname = inHostname;
		this.path = inPath;
		this.fragment = inFragment;
	}
	package this(Proto protocol, string hostname, string path, URLParameters params, string fragment) pure @safe nothrow {
		this.protocol = protocol;
		this.hostname = hostname;
		this.path = path;
		this.params = params;
		this.fragment = fragment;
	}
	package this(Proto protocol, string hostname, string path, const URLParameters params, string fragment) const pure @safe nothrow {
		this.protocol = protocol;
		this.hostname = hostname;
		this.path = path;
		this.params = params;
		this.fragment = fragment;
	}
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
	/// Construct a URL from a string
	this(string str, Flag!"SemicolonQueryParameters" semicolonQueryParameters = Flag!"SemicolonQueryParameters".no) @safe pure nothrow {
		import std.algorithm.iteration : substitute;
		import std.utf : byCodeUnit;
		str = str.byCodeUnit.substitute!('\\', '/').array;
		this.protocol = str.urlProtocol;
		auto fragSplit = findSplit(str, "#");
		str = fragSplit[0];
		this.fragment = fragSplit[2];
		auto splitComponents = str.split("/");
		if (splitComponents.length > 0) {
			this.hostname = getHostname(str, this.protocol);
			//Get Path
			if (this.protocol.among(Proto.Unknown, Proto.None)) {
				this.path = splitComponents.join("/");
			} else {
				this.path = only("").chain(splitComponents.drop(3)).join("/");
			}
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
		if (path.split("/").length == 0) {
			return "";
		}
		return path.split("/")[$-1];
	}
	/++
	 + Returns a new URL with the specified set of parameters, replacing existing parameters.
	 +/
	URL withReplacedParams(T)(T inParams) const if (isURLEncodable!T) {
		auto url = URL(protocol, hostname, path, inParams);
		foreach (k, v; params) {
			if (k !in url.params) {
				url.params[k] ~= v;
			}
		}
		return url;
	}
	/++
	 + Returns a new URL with the specified set of parameters added.
	 +/
	URL withNewParams(T)(T inParams) const if (isURLEncodable!T) {
		auto url = URL(protocol, hostname, path, inParams);
		foreach (k, v; params) {
			url.params ~= QueryParameter(k, v);
		}
		return url;
	}
	/++
	 + Transforms the parameters for this URL to a URL-encoded string.
	 +/
	string paramString() nothrow const @safe pure {
		if (params.empty) return "";
		string[] parameterPrintable;
		try {
			foreach (parameter, value; params) {
				if (value == "") {
					parameterPrintable ~= parameter.encodeComponentSafe().replace(":", "%3A").replace("+", "%2B");
				} else {
					parameterPrintable ~= format("%s=%s", parameter.encodeComponentSafe().replace(":", "%3A").replace("+", "%2B"), value.encodeComponentSafe().replace(":", "%3A").replace("+", "%2B"));
				}
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
	URL absoluteURL(in URL urlB) const @safe pure {
		if ((this == urlB) || (urlB == const(URL).init)) {
			return URL(protocol, hostname, path, params);
		}
		Proto newProto = urlB.protocol.among(Proto.None, Proto.Same) ? protocol : urlB.protocol;
		immutable newHostname = (urlB.hostname != "") ? urlB.hostname : hostname;
		immutable newPath = chainURL("/", path, urlB.path).asNormalizedURL.chain(only('/').take((urlB.path.length > 1) && urlB.path.endsWith('/'))).array;
		return URL(newProto, newHostname, newPath, params).withReplacedParams(urlB.params);
	}
	///ditto
	URL absoluteURL(string urlB) const pure @safe {
		return absoluteURL(URL(urlB));
	}
	///ditto
	URL absoluteURL(T)(string urlB, T params) const if (isURLEncodable!T) {
		return absoluteURL(URL(urlB).withReplacedParams(params));
	}
	///ditto
	URL absoluteURL(string fmt, Args...)(Args fmtParams) const {
		import std.format : format;
		return absoluteURL(URL(format!fmt(fmtParams)));
	}
	void toString(T)(T sink, FormatSpec!char fmt = FormatSpec!char.init) const if (isOutputRange!(T, char[])) {
		bool printSlash;
		if (protocol == Proto.HTTPS) {
			sink("https://");
			sink(hostname);
			printSlash = true;
		} else if (protocol == Proto.HTTP) {
			sink("http://");
			sink(hostname);
			printSlash = true;
		} else if ((protocol == Proto.None) && (hostname != hostname.init)) {
			throw new Exception("Invalid URL State");
		} else if (protocol == Proto.Same) {
			sink("//");
			sink(hostname);
			printSlash = true;
		}

		if (printSlash && !hostname.endsWith('/') && (path != path.init) && (path[0] != '/')) {
			sink("/");
		}

		sink(encodePathComponentSafe(path));

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
		if (fragment != null) {
			sink("#");
			sink(fragment);
		}
	}
	immutable(URL) idup() @safe pure const {
		return immutable URL(protocol, hostname, path, params.idup, fragment);
	}
	URL dup() @safe pure const nothrow {
		return URL(protocol, hostname, path, params.dup, fragment);
	}
	int opCmp(const URL other) @safe pure const {
		if (auto protocolComparison = this.protocol - other.protocol) {
			return protocolComparison;
		}
		if (auto hostComparison = cmp(this.hostname, other.hostname)) {
			return hostComparison;
		}
		if (auto pathComparison = cmp(this.path, other.path)) {
			return pathComparison;
		}
		if (auto paramsComparison = cmp(this.paramString, other.paramString)) {
			return paramsComparison;
		}
		if (auto fragmentComparison = cmp(this.fragment, other.fragment)) {
			return fragmentComparison;
		}
		return 0;
	}
}
@safe pure unittest {
	const a = URL(URL.Proto.HTTP, "localhost", "/", ["a": "b"]);
	const b = URL(URL.Proto.HTTP, "localhost", "/");
}
@safe pure unittest {
	assert(URL("http://url.example/?a=b#hello").text() == "http://url.example/?a=b#hello", "Simple complete URL failure");
	assert(URL("http://url.example/#hello").text() == "http://url.example/#hello", "Simple URL with fragment failure");
	assert(URL("http://url.example#hello").text() == "http://url.example#hello", "Simple URL with fragment, no trailing / on hostname failure");
	assert(URL("https://url.example/?a=b").text() == "https://url.example/?a=b", "Simple complete URL (https) failure");
	assert(URL("http://url.example").text() == "http://url.example", "Simple complete URL (no ending slash) failure");
	assert(URL("http:/url.example").text() == "http://url.example", "Simple complete URL (no double protocol slash) failure");
	assert(URL("something").text() == "something", "Path-only relative URL recreation failure");
	assert(URL("/something").text() == "/something", "Path-only absolute URL recreation failure");
	assert(URL("/something?a=b:d").text() == "/something?a=b%3Ad");
	assert(URL("http://url.example/?a=b&&").text() == "http://url.example/?a=b");
	assert(URL("http://url.example/blah().file").text() == "http://url.example/blah%28%29.file");
	assert(URL("http://url.example/?a=b;;", Flag!"SemicolonQueryParameters".yes).text() == "http://url.example/?a=b");
	assert(URL("https://example.com").absoluteURL("/it%E2%80%99s").text() == "https://example.com/it%E2%80%99s");
	with(URL("something")) {
		assert(protocol == Proto.None);
		assert(hostname == "");
		assert(path == "something");
	}
	assert(URL("http://url.example/dir/").text() == "http://url.example/dir/", "Trailing slash");
	assert(URL("http://url.example/").absoluteURL("/dir/").text() == "http://url.example/dir/", "Trailing slash");
}
@safe pure unittest {
	struct Test {
		string a;
	}
	assert(URL("http://url.example/").withReplacedParams(["a":"b"]).text() == "http://url.example/?a=b", "Simple complete URL + assoc param failure");
	assert(URL("http://url.example/").withReplacedParams(["a":["b"]]).text() == "http://url.example/?a=b", "Simple complete URL + assoc arr param failure");
	assert(URL("http://url.example/").withReplacedParams(Test("b")).text() == "http://url.example/?a=b", "Simple complete URL + struct param failure");
	assert(URL("http://url.example/?a=c").withReplacedParams(["a":"b"]).text() == "http://url.example/?a=b", "Simple complete URL + assoc param override failure");
	assert(URL("http://url.example/?test").withReplacedParams(["test2": ["value"]]).params == ["test":[""], "test2":["value"]], "Merged parameters failure");
}
@safe pure unittest {
	assert(URL("http://url.example").protocol == URL.Proto.HTTP, "HTTP detection failure");
	assert(URL("https://url.example").protocol == URL.Proto.HTTPS, "HTTPS detection failure");
	assert(URL("url.example").protocol == URL.Proto.None, "No-protocol detection failure");
	assert(URL("HTTP://URL.EXAMPLE").protocol == URL.Proto.HTTP, "HTTP caps detection failure");
	assert(URL("HTTPS://URL.EXAMPLE").protocol == URL.Proto.HTTPS, "HTTPS caps detection failure");
	assert(URL("URL.EXAMPLE").protocol == URL.Proto.None, "No-protocol caps detection failure");
	assert(URL("http:url.example").protocol == URL.Proto.HTTP);
	assert(URL("/something?a=b:d").protocol == URL.Proto.None);
}
@safe pure unittest {
	assert(URL("http://url.example").hostname == "url.example", "HTTP hostname detection failure");
	assert(URL("https://url.example").hostname == "url.example", "HTTPS hostname detection failure");
	assert(URL("http:/url.example").hostname == "url.example", "HTTP hostname (missing double slash) detection failure");
	assert(URL("http://url.example/dir").hostname == "url.example", "HTTP hostname detection failure");
	assert(URL("HTTP://URL.EXAMPLE").hostname == "url.example", "HTTP caps hostname detection failure");
	assert(URL("HTTPS://URL.EXAMPLE").hostname == "url.example", "HTTPS caps hostname detection failure");
	assert(URL("http://URL.EXAMPLE/DIR").hostname == "url.example", "path+caps hostname detection failure");
	assert(URL("HTTP:url.example").hostname == "url.example");
	assert(URL("/something?a=b:d").hostname == "");
}
@safe pure unittest {
	assert(URL("http://url.example/path").path == "/path", "URL path failure");
}
@safe pure unittest {
	assert(URL("http://url.example").absoluteURL("https://url.example").text() == "https://url.example/", "Switching protocol (string) failure");
	assert(URL("http://url.example").absoluteURL(URL("https://url.example")).text() == "https://url.example/", "Switching protocol (struct) failure");
	assert(URL("http://url.example").absoluteURL("http://url.example").text() == "http://url.example", "Identical URL (string) failure");
	assert(URL("http://url.example").absoluteURL(URL("http://url.example")).text() == "http://url.example", "Identical URL (struct) failure");
	assert(URL("http://url.example").absoluteURL("/something").text() == "http://url.example/something", "Root-relative URL (string) failure");
	assert(URL("http://url.example").absoluteURL(URL("/something")).text() == "http://url.example/something", "Root-relative URL (struct) failure");
	assert(URL("http://url.example").absoluteURL("//different.example").text() == "http://different.example/", "Same-protocol relative URL (string) failure");
	assert(URL("http://url.example").absoluteURL(URL("//different.example")).text() == "http://different.example/", "Same-protocol relative URL (struct) failure");
	assert(URL("http://url.example").absoluteURL("..").text() == "http://url.example/", "Relative parent URL (string) failure");
	assert(URL("http://url.example/dir").absoluteURL(".").text() == "http://url.example/dir", "Dot URL (string) failure");
	assert(URL("http://url.example/dir").absoluteURL(URL(".")).text() == "http://url.example/dir", "Dot URL (struct) failure");
	assert(URL("http://url.example/dir").absoluteURL("..").text() == "http://url.example/", "Relative parent URL (string) failure");
	assert(URL("http://url.example/dir").absoluteURL(URL("..")).text() == "http://url.example/", "Relative parent URL (struct) failure");
	assert(URL("http://url.example/dir").absoluteURL("/different").text() == "http://url.example/different", "Root-relative (w/dir) URL (string) failure");
	assert(URL("http://url.example/dir").absoluteURL(URL("/different")).text() == "http://url.example/different", "Root-relative (w/dir) URL (struct) failure");
	assert(URL("http://url.example/dir").absoluteURL("different").text() == "http://url.example/dir/different", "cwd-relative (w/dir) URL (string) failure");
	assert(URL("http://url.example/dir").absoluteURL(URL("different")).text() == "http://url.example/dir/different", "cwd-relative (w/dir) URL (struct) failure");
	assert(URL("http://url.example").absoluteURL!"/%s"("test").text() == "http://url.example/test");
	assert(URL("http://url.example").absoluteURL!"/%s"(5).text() == "http://url.example/5");
	assert(URL("http://url.example/").absoluteURL("/", ["hello": "world"]).text == "http://url.example/?hello=world");
	assert(URL("http://url.example/somewhere/").absoluteURL("http://url.example/somewhere").text == "http://url.example/somewhere");
	assert(URL("http://url.example/somewhere").absoluteURL("?param=value").text == "http://url.example/somewhere?param=value");
}
@safe pure unittest {
	assert(URL("").params == URL.params.init, "URIArguments: Empty string failure");
	assert(URL("http://url.example/?hello=world").params == ["hello":["world"]], "URIArguments: Simple test failure");
	assert(URL("http://url.example/?hello=world+bar").params == ["hello":["world bar"]], "URIArguments: Plus as space in value failure");
	assert(URL("http://url.example/?hello+bar=world").params == ["hello bar":["world"]], "URIArguments: Plus as space in key failure");
	assert(URL("http://url.example/?hello=world%20bar").params == ["hello":["world bar"]], "URIArguments: URL decoding in value failure");
	assert(URL("http://url.example/?hello%20bar=world").params == ["hello bar":["world"]], "URIArguments: URL decoding in key failure");
	assert(URL("http://url.example/?hello").params == ["hello":[""]], "URIArguments: Key only failure");
	assert(URL("http://url.example/?hello=").params == ["hello":[""]], "URIArguments: Empty value failure");
	assert(URL("http://url.example/?hello+").params == ["hello ":[""]], "URIArguments: Key only with plus sign failure");
	assert(URL("http://url.example/?hello+=").params == ["hello ":[""]], "URIArguments: Empty value with plus sign failure");
	assert(URL("http://url.example/?hello+=").text == "http://url.example/?hello%20");
	assert(URL("http://url.example/?hello=1&hello=2").params == ["hello":["1", "2"]], "URIArguments: Duplicate key failure");
	auto url = URL("http://url.example");
	url.params["hello"] = ["+"];
	assert(url.text == "http://url.example/?hello=%2B");
	assert(format!"%n"(URL("http://url.example/?hello")) == "http://url.example/");
	assert(format!"%s"(URL("http://url.example/?hello")) == "http://url.example/?hello");
	assert(URL("http://url.example/?hello=world#fragment").params == ["hello":["world"]], "URIArguments: Simple test with fragment failure");
}
@safe pure unittest {
	assert(URL("http://url.example/?hello=1;hello2=2", Flag!"SemicolonQueryParameters".yes).params == ["hello":["1"], "hello2":["2"]], "URIArguments (semicolons): key failure");
	assert(URL("http://url.example/?hello=1;hello=2", Flag!"SemicolonQueryParameters".yes).params == ["hello":["1", "2"]], "URIArguments (semicolons): Duplicate key failure");
}


// The following code has been shamelessly borrowed from phobos's std.path
// See: https://github.com/dlang/phobos

private auto chainURL(R1, R2, Ranges...)(R1 r1, R2 r2, Ranges ranges)
if ((isRandomAccessRange!R1 && hasSlicing!R1 && hasLength!R1 && isSomeChar!(ElementType!R1) ||
	isNarrowString!R1 &&
	!isConvertibleToString!R1) &&
	(isRandomAccessRange!R2 && hasSlicing!R2 && hasLength!R2 && isSomeChar!(ElementType!R2) ||
	isNarrowString!R2 &&
	!isConvertibleToString!R2) &&
	(Ranges.length == 0 || is(typeof(chainURL(r2, ranges))))
	)
{
	static bool isRooted(R2 path) {
		return (path.length >= 1 && path[0] == '/');
	}
	static if (Ranges.length) {
		return chainURL(chainURL(r1, r2), ranges);
	} else {
		import std.range : only, chain;
		import std.utf : byUTF;

		alias CR = Unqual!(ElementEncodingType!R1);
		auto sep = only(CR('/'));
		bool usesep = false;

		auto pos = r1.length;

		if (pos) {
			if (isRooted(r2)) {
				pos = 0;
			} else if (!isURLSeparator(r1[pos - 1])) {
				usesep = true;
			}
		}
		if (!usesep) {
			sep.popFront();
		}
		return chain(r1[0 .. pos].byUTF!CR, sep, r2.byUTF!CR);
	}
}

private auto asNormalizedURL(R)(return scope R path)
if (isSomeChar!(ElementEncodingType!R) &&
	(isRandomAccessRange!R && hasSlicing!R && hasLength!R || isNarrowString!R) &&
	!isConvertibleToString!R)
{
	import std.algorithm.searching : startsWith;
	alias C = Unqual!(ElementEncodingType!R);
	alias S = typeof(path[0 .. 0]);

	static struct Result {
		@property bool empty() {
			return c == c.init;
		}

		@property C front() {
			return c;
		}

		void popFront() {
			C lastc = c;
			c = c.init;
			if (!element.empty) {
				c = getElement0();
				return;
			}
		  L1:
			while (1) {
				if (elements.empty) {
					element = element[0 .. 0];
					return;
				}
				element = elements.front;
				elements.popFront();
				if (isDot(element) || (rooted && isDotDot(element))) {
					continue;
				}

				if (rooted || !isDotDot(element)) {
					int n = 1;
					auto elements2 = elements.save;
					while (!elements2.empty) {
						auto e = elements2.front;
						elements2.popFront();
						if (isDot(e)) {
							continue;
						}
						if (isDotDot(e)) {
							--n;
							if (n == 0) {
								elements = elements2;
								element = element[0 .. 0];
								continue L1;
							}
						}
						else {
							++n;
						}
					}
				}
				break;
			}

			if (lastc == '/' || lastc == lastc.init) {
				c = getElement0();
			} else {
				c = '/';
			}
		}

		static if (isForwardRange!R) {
			@property auto save() {
				auto result = this;
				result.element = element.save;
				result.elements = elements.save;
				return result;
			}
		}

	  private:
		this(R path) {
			element = rootName(path);
			auto i = element.length;
			while (i < path.length && isURLSeparator(path[i])) {
				++i;
			}
			rooted = i > 0;
			elements = urlSplitter(path[i .. $]);
			popFront();
			if (c == c.init && path.length) {
				c = C('.');
			}
		}

		C getElement0() {
			static if (isNarrowString!S)  { // avoid autodecode
				C c = element[0];
				element = element[1 .. $];
			} else {
				C c = element.front;
				element.popFront();
			}
			return c;
		}

		// See if elem is "."
		static bool isDot(S elem) {
			return elem.length == 1 && elem[0] == '.';
		}

		// See if elem is ".."
		static bool isDotDot(S elem) {
			return elem.length == 2 && elem[0] == '.' && elem[1] == '.';
		}

		bool rooted;	// the path starts with a root directory
		C c;
		S element;
		typeof(urlSplitter(path[0 .. 0])) elements;
	}

	return Result(path);
}

private auto urlSplitter(R)(R path)
if ((isRandomAccessRange!R && hasSlicing!R ||
	isNarrowString!R) &&
	!isConvertibleToString!R)
{
	static struct PathSplitter {
		@property bool empty() const {
			return pe == 0;
		}

		@property R front() {
			assert(!empty);
			return _path[fs .. fe];
		}

		void popFront() {
			assert(!empty);
			if (ps == pe) {
				if (fs == bs && fe == be) {
					pe = 0;
				} else {
					fs = bs;
					fe = be;
				}
			} else {
				fs = ps;
				fe = fs;
				while (fe < pe && !isURLSeparator(_path[fe])) {
					++fe;
				}
				ps = ltrim(fe, pe);
			}
		}

		@property R back() {
			assert(!empty);
			return _path[bs .. be];
		}

		void popBack() {
			assert(!empty);
			if (ps == pe) {
				if (fs == bs && fe == be) {
					pe = 0;
				}
				else {
					bs = fs;
					be = fe;
				}
			}
			else {
				bs = pe;
				be = bs;
				while (bs > ps && !isURLSeparator(_path[bs - 1])) {
					--bs;
				}
				pe = rtrim(ps, bs);
			}
		}
		@property auto save() { return this; }


	private:
		R _path;
		size_t ps, pe;
		size_t fs, fe;
		size_t bs, be;

		this(R p) {
			if (p.empty) {
				pe = 0;
				return;
			}
			_path = p;

			ps = 0;
			pe = _path.length;

			// If path is rooted, first element is special
			if (_path.length >= 1 && isURLSeparator(_path[0])) {
				fs = 0;
				fe = 1;
				ps = ltrim(fe, pe);
			} else {
				popFront();
			}

			if (ps == pe) {
				bs = fs;
				be = fe;
			} else {
				pe = rtrim(ps, pe);
				popBack();
			}
		}

		size_t ltrim(size_t s, size_t e) {
			while (s < e && isURLSeparator(_path[s])) {
				++s;
			}
			return s;
		}

		size_t rtrim(size_t s, size_t e) {
			while (s < e && isURLSeparator(_path[e - 1])) {
				--e;
			}
			return e;
		}
	}

	return PathSplitter(path);
}

@safe pure unittest {
	import std.array : array;
	assert(chainURL("/", "example").asNormalizedURL.array == "/example");
	assert(chainURL("/", "..").asNormalizedURL.array == "/");
	assert(chainURL("/dir", "..").asNormalizedURL.array == "/");
	assert(chainURL("/dir/dir2", "..").asNormalizedURL.array == "/dir");
	assert(chainURL("/dir/dir2", ".").asNormalizedURL.array == "/dir/dir2");
}

private auto rootName(R)(R path)
{
	if (!path.empty && isURLSeparator(path[0])) {
		return path[0 .. 1];
	}
	return path[0 .. 0];
}

private bool isURLSeparator(dchar c)  @safe pure nothrow @nogc
{
    if (c == '/') return true;
    return false;
}
