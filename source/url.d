module url;

alias URLParameters = string[string];
alias URLHeaders = string[string];
alias URLString = string;
enum Proto { Unknown, HTTP, HTTPS, FTP, Same, None};
private alias ProtoEnum = Proto;

@property Proto protocol(in string URL) pure @safe {
	import std.string : toLower;
	if (URL.length >= 6) {
		if (URL[0..5].toLower() == "http:")
			return Proto.HTTP;
		else if (URL[0..5].toLower() == "https")
			return Proto.HTTPS;
	} 
	if ((URL.length >= 2) && (URL[0..2] == "//"))
		return Proto.Same;
	else if ((URL.length >= 1) && URL[0] == '/')
		return Proto.None;
	else if ((URL.length >= 1) && URL[0] == '.')
		return Proto.None;
	return Proto.Unknown;
}
string getHostname(in string URL, in Proto Protocol) pure {
	import std.string : toLower, split;
	auto splitURL = URL.split("/");
	if (Protocol == Proto.Unknown)
		return splitURL[0].toLower();
	else if (Protocol != Proto.None)
		return splitURL[2].toLower();
	return "";
}
struct URL {
	alias Proto = ProtoEnum;
	string[string] Params;
	Proto Protocol;
	string Hostname;
	string Path;
	this(Proto protocol, string hostname, string path, URLParameters inParams = URLParameters.init) @safe pure {
		Protocol = protocol;
		Hostname = hostname;
		Path = path;
		Params = inParams;
	}
	this(URLString str, URLParameters inParams = URLParameters.init) {
		auto u = splitURL(str, inParams);
		this(u.Protocol, u.Hostname, u.Path, u.Params);
	}
	static auto splitURL(URLString str, in URLParameters inParams = URLParameters.init) {
		import std.array : replace;
		import std.algorithm : find;
		import std.string : toLower, split, join;
		import std.uri : decode;
		URL url;
		url.Protocol = str.protocol;

		auto splitURL = str.split("/");
		if (splitURL.length > 0) {
			url.Hostname = getHostname(str, url.Protocol);
			//Get Path
			if (url.Protocol == Proto.Unknown)
				url.Path = splitURL[0..$].join("/");
			else if (url.Protocol == Proto.None)
				url.Path = splitURL[0..$].join("/");
			else
				url.Path = splitURL[3..$].join("/");
			
			auto existingParameters = url.Path.find("?");
			if (existingParameters.length > 0) {
				foreach (arg; existingParameters[1..$].split("&")) {
					auto splitArg = arg.split("=");
					if (splitArg.length > 1)
						url.Params[decode(splitArg[0].replace("+", " "))] = decode(splitArg[1].replace("+", " "));
					else
						url.Params[decode(arg.replace("+", " "))] = "";
				}
				url.Path = url.Path.split("?")[0];
			}
		}
		foreach (k,v; inParams)
			url.Params[k] = v;
		return url;
	}
	@property string Filename() nothrow const pure {
		import std.string : split;
		return Path.split("/")[$-1];
	}
	@property string paramString() nothrow const @trusted {
		import std.uri;
		import std.string : format, join, replace;
		if (Params == null) return "";
		scope(failure) return "";
		string[] parameterPrintable;
		foreach (parameter, value; Params)
			if (value == "")
				parameterPrintable ~= parameter.encode().replace(":", "%3A");
			else
				parameterPrintable ~= format("%s=%s", parameter.encode().replace(":", "%3A"), value.encode().replace(":", "%3A"));
		return "?"~parameterPrintable.join("&");
	}
	URL absoluteURL(string urlB, string[string] params = null) const {
		return absoluteURL(URL(urlB, params));
	}
	URL absoluteURL(in URL urlB) const {
		import std.string : split, join;
		Proto ProtoCopy = Protocol;
		Proto ProtoCopyB = urlB.Protocol;
		auto HostnameCopy = Hostname.idup;
		auto PathCopy = Path.idup;
		auto ParamsCopy = cast(URLParameters)Params.dup;
		if (urlB.toString() == "")
			return URL(ProtoCopy, HostnameCopy, PathCopy, ParamsCopy);
		if (this == urlB)
			return URL(ProtoCopy, HostnameCopy, PathCopy, ParamsCopy);
		if ((urlB.Protocol == Proto.HTTP) || (urlB.Protocol == Proto.HTTPS))
			return URL(ProtoCopyB, urlB.Hostname.idup, urlB.Path.idup, cast(URLParameters)urlB.Params.dup);
		if ((urlB.Protocol == Proto.None) && (urlB.Path == "."))
			return URL(ProtoCopy, HostnameCopy, PathCopy, ParamsCopy);
		if ((urlB.Protocol == Proto.None) && (urlB.Path == ".."))
			return URL(ProtoCopy, HostnameCopy, PathCopy.split("/")[0..$-1].join("/"), ParamsCopy);
		if (urlB.Protocol == Proto.None)
			return URL(ProtoCopy, HostnameCopy, urlB.Path.idup, cast(URLParameters)urlB.Params.dup);
		if (urlB.Protocol == Proto.Same)
			return URL(ProtoCopy, urlB.Hostname, urlB.Path.idup, cast(URLParameters)urlB.Params.dup);
		return URL(ProtoCopy, HostnameCopy, PathCopy ~ "/" ~ urlB.Path, ParamsCopy);
	}
	string toString() const @safe {
		return toString(true);
	}
	string toString(bool includeParameters) const @safe {
		string output;
		if (Protocol == Proto.HTTPS)
			output ~= "https://" ~ Hostname;
		else if (Protocol == Proto.HTTP)
			output ~= "http://" ~ Hostname;
		else if ((Protocol == Proto.None) && (Hostname != Hostname.init))
			throw new Exception("Invalid URL State");
		else if (Protocol == Proto.Same)
			output ~= "//" ~ Hostname;
		if ((output.length > 0) && (output[$-1] != '/') && (Path != Path.init) && (Path[0] != '/'))
			output ~= "/";
		output ~= Path;
		if (includeParameters) {
			if (paramString() != "") {
				if (Path == Path.init)
					output ~= "/";
				output ~= paramString();	
			}
		}
		return output;
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
	assert(URL("http://url.example").Protocol == Proto.HTTP, "HTTP detection failure");
	assert(URL("https://url.example").Protocol == Proto.HTTPS, "HTTPS detection failure");
	assert(URL("url.example").Protocol == Proto.Unknown, "No-protocol detection failure");
	assert(URL("HTTP://URL.EXAMPLE").Protocol == Proto.HTTP, "HTTP caps detection failure");
	assert(URL("HTTPS://URL.EXAMPLE").Protocol == Proto.HTTPS, "HTTPS caps detection failure");
	assert(URL("URL.EXAMPLE").Protocol == Proto.Unknown, "No-protocol caps detection failure");
}
unittest {
	assert(URL("http://url.example").Hostname == "url.example", "HTTP hostname detection failure");
	assert(URL("https://url.example").Hostname == "url.example", "HTTPS hostname detection failure");
	assert(URL("url.example").Hostname == "url.example", "No-protocol hostname detection failure");
	assert(URL("http://url.example/dir").Hostname == "url.example", "HTTP hostname detection failure");
	assert(URL("HTTP://URL.EXAMPLE").Hostname == "url.example", "HTTP caps hostname detection failure");
	assert(URL("HTTPS://URL.EXAMPLE").Hostname == "url.example", "HTTPS caps hostname detection failure");
	assert(URL("URL.EXAMPLE").Hostname == "url.example", "No-protocol caps hostname detection failure");
	assert(URL("http://URL.EXAMPLE/DIR").Hostname == "url.example", "path+caps hostname detection failure");
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
	assert(URL("").Params is null, "URIArguments: Empty string failure");
	assert(URL("http://url.example/?hello=world").Params == ["hello":"world"], "URIArguments: Simple test failure");
	assert(URL("http://url.example/?hello=world+butt").Params == ["hello":"world butt"], "URIArguments: Plus as space in value failure");
	assert(URL("http://url.example/?hello+butt=world").Params == ["hello butt":"world"], "URIArguments: Plus as space in key failure");
	assert(URL("http://url.example/?hello=world%20butt").Params == ["hello":"world butt"], "URIArguments: URL decoding in value failure");
	assert(URL("http://url.example/?hello%20butt=world").Params == ["hello butt":"world"], "URIArguments: URL decoding in key failure");
	assert(URL("http://url.example/?hello").Params == ["hello":""], "URIArguments: Key only failure");
	assert(URL("http://url.example/?hello=").Params == ["hello":""], "URIArguments: Empty value failure");
	assert(URL("http://url.example/?hello+").Params == ["hello ":""], "URIArguments: Key only with plus sign failure");
	assert(URL("http://url.example/?hello+=").Params == ["hello ":""], "URIArguments: Empty value with plus sign failure");
}
unittest {
	assert(URL("http://url.example/?test", ["test2": "value"]).Params == ["test":"", "test2":"value"], "Merged parameters failure");
}