module httpinterface;

public import json : Json;
public import arsd.dom : Document, Element;

private import std.stdio;

version(Windows) int maxPath = 260;
version(Posix) int maxPath = 255;
public uint defaultMaxTries = 5;
void Log(string file = __FILE__, int line = __LINE__)(string msg) {
	version(Have_loggins) {
		import loggins;
		LogDebugV!(LoggingFlags.NoCut | LoggingFlags.NewLine, file, line)("%s", msg);
	} else {
		debug writefln(msg);
	}
}
string fixPath(in string inPath) in {
	assert(inPath != "", "No path");
} body {
	import std.algorithm : min;
	import std.string : removechars;
	import std.path;
	string dest = inPath;
	version(Windows) dest = dest.removechars("\"?<>:|*");
	if (dest[$-1] == '.')
		dest ~= "tmp";
	if (dest.absolutePath().length > maxPath) {
		dest = (dest.dirName() ~ "/" ~ dest.baseName()[0..min($,(maxPath-10)-(dest.absolutePath().dirName() ~ "/" ~ dest.absolutePath().extension()).length)] ~ dest.extension()).buildNormalizedPath();
	}
	version(Windows) {
		dest = "\\\\?\\" ~ dest.absolutePath().buildNormalizedPath();
	}
	return dest;
}
unittest {
	import std.file, std.algorithm : map;
	string[] pathsToTest = ["short", "loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong", "invalid&"];
	foreach (path; map!fixPath(pathsToTest)) {
		try {
			mkdirRecurse(path);
			assert(exists(path), "Created nonexistant path: " ~ path);
			rmdir(path);
		} catch (Exception e) {
			assert(false, "Bad path: " ~ path ~ "(" ~ e.msg ~ ")"); 
		}
	}
}
//Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.102 Safari/537.36
HTTPFactory httpfactory;
static this() {
	httpfactory = new HTTPFactory;
}
class HTTPFactory {
	public string CookieJar;
	public uint RetryCount = 5;
	private HTTP[string] activeHTTP;
	HTTP spawn(in URL inURL, in string[string] reqHeaders = null) {
		if (inURL.Hostname !in activeHTTP) {
			Log("Spawning new HTTP instance for "~inURL.toString());
			activeHTTP[inURL.Hostname] = new HTTP(inURL, reqHeaders);
			activeHTTP[inURL.Hostname].CookieJar = CookieJar;
		}
		return activeHTTP[inURL.Hostname];
	}
}
class HTTP {
	import std.net.curl : CurlException, CurlHTTP = HTTP;
	public const(URL) url;

	public uint retryCount = 5;

	private CurlHTTP HTTPClient;
	private string[string] _headers;
	private string _cookiepath;
	this(in string inURL, in string[string] reqHeaders = null) @trusted {
		this(new URL(inURL), reqHeaders);
	}
	this(in URL inURL, in string[string] reqHeaders = null) @trusted {
		import etc.c.curl;
		retryCount = defaultMaxTries;
		url = inURL;

		HTTPClient = CurlHTTP();
		HTTPClient.verifyPeer(false);
		HTTPClient.maxRedirects(uint.max);
		headers(reqHeaders);
	}
	this(in string hostname, in bool https, in string[string] reqHeaders) {
		this("http"~(https ? "s" : "")~"://"~hostname, reqHeaders);
	}
	~this() nothrow {
		scope (failure) return;
		HTTPClient.shutdown();
	}
	@property string[string] headers(in string[string] newHeaders) @trusted {
		//HTTPClient.clearRequestHeaders();
		foreach (key, value; newHeaders)
			HTTPClient.addRequestHeader(key, value);
		foreach (k,v; newHeaders)
			_headers[k] = v;
		return _headers;
	}
	@property string[string] headers() @safe {
		return _headers;
	}
	@property string CookieJar(string path) @trusted {
		import std.path;
		import std.file;
		assert(dirName(path).isDir, dirName(path)~" is not a directory!");
		_cookiepath = path;
		HTTPClient.setCookieJar(path);
		return path;
	}
	@property string CookieJar() @safe {
		return _cookiepath;
	}
	Response get(in URL url) {
		return get(url.Path, url.Params);
	}
	Response post(in URL url, in string[string] data) {
		return post(url.Path, data, url.Params);
	}
	Response post(in URL url, in string data) {
		return post(url.Path, data, url.Params);
	}
	Response get(in string path, in string[string] params = null) @trusted {
		import std.string : format;
		auto output = this.new Response(HTTPClient, new URL(url.Protocol, url.Hostname, path, params));
		output.method = CurlHTTP.Method.get;
		output.onReceive = null;
		output.maxTries = retryCount;
		Log(format("Spawning GET Response for host %s, path %s", output.url.Hostname, output.url.Path));
		return output;
	}
	Response post(in string path, in string inData, in string[string] params = null) @trusted {
		import std.string : format, representation;
		import std.algorithm : min;
		import etc.c.curl : CurlSeekPos, CurlSeek;
		auto output = this.new Response(HTTPClient, new URL(url.Protocol, url.Hostname, path, params));
		output.method = CurlHTTP.Method.post;
		//output.url = new URL(url.Protocol, url.Hostname, path, params);
		output.onReceive = null;
		output.maxTries = retryCount;
		auto data = inData.representation().dup;
		output.contentLength = cast(uint)data.length;
		auto remainingData = data;
	    output.onSend = delegate size_t(void[] buf)
	    {
	        size_t minLen = min(buf.length, remainingData.length);
	        if (minLen == 0) return 0;
	        buf[0..minLen] = remainingData[0..minLen];
			Log(format("POSTING %s", remainingData[0..minLen]));
	        remainingData = remainingData[minLen..$];
	        return minLen;
	    };
	    output.onSeek = delegate(long offset, CurlSeekPos mode)
	    {
	        switch (mode)
	        {
	            case CurlSeekPos.set:
	                remainingData = data[cast(size_t)offset..$];
	                return CurlSeek.ok;
	            default:
	                // As of curl 7.18.0, libcurl will not pass
	                // anything other than CurlSeekPos.set.
	                return CurlSeek.cantseek;
	        }
	    };
		Log(format("Spawning POST Response for host %s, path %s", output.url.Hostname, output.url.Path));
		return output;
	}
	Response post(in string path, in string[string] data, in string[string] params = null) @trusted {
		string[] newdata;
		foreach (key, val; data)
			newdata ~= std.uri.encode(key) ~ "=" ~ std.uri.encode(val);
		return post(path, std.string.join(newdata, "&"), params);
	}
	override string toString() {
		return url.toString();
	}
	class Response {
		private import etc.c.curl : CurlSeekPos, CurlSeek;
		private struct OAuthParams {
			string consumerToken;
			string consumerSecret;
			string token;
			string tokenSecret;
		}
		const(ubyte)[] _content;
		string[string] _headers;
		private CurlHTTP client;
		private bool fetched = false;
		private bool checkNoContent = false;
		uint maxTries;
		URL url;
		size_t delegate(ubyte[]) onReceive;
		CurlSeek delegate(long offset, CurlSeekPos mode) onSeek;
		size_t delegate(void[] buf) onSend;
		uint contentLength;
		CurlHTTP.Method method;
		private string MD5hash;
		private string SHA1hash;
		private OAuthParams oAuthParams;
		ushort statusCode;
		//@disable this();
		invariant() {
			assert(url !is null, "Associated URL missing");
			assert((url.Protocol != URL.Proto.Unknown) && (url.Protocol != URL.Proto.None) && (url.Protocol != URL.Proto.Same), "No protocol specified in URL");
		}
		private this(CurlHTTP inClient, URL initial) {
			client = inClient;
			url = initial;
		}
		void reset() {
			_content = [];
			_headers = null;
			fetched = false;
		}
		@property string filename() nothrow {
			return url.Filename;
		}
		void saveTo(in string dest) {
			version(Windows) {
				auto outFile = new std.stream.File(dest.fixPath(), std.stream.FileMode.OutNew);
				scope(exit) 
					if (outFile.isOpen) {
						outFile.flush();
						outFile.close();
					}
				onReceive = (ubyte[] data) { _content ~= data; outFile.write(data); return data.length; };
				uint trycount = 0;
				outFile.seekSet(0);
				if (!fetched)
					fetchContent();
				else
					outFile.write(_content);
			} else {
				auto outFile = File(dest.fixPath(), "wb");
				scope(exit) 
					if (outFile.isOpen) {
						outFile.flush();
						outFile.close();
					}
				onReceive = (ubyte[] data) { _content ~= data; outFile.rawWrite(data); return data.length; };
				uint trycount = 0;
				outFile.seek(0);
				if (!fetched)
					fetchContent();
				else
					outFile.rawWrite(_content);
			}
		}
		@property ushort status() {
			if (!fetched)
				fetchContent(true);
			return statusCode;
		}
		Response guaranteeData(bool val = true) {
			checkNoContent = val;
			return this;
		}
		Response setVerbosity(bool verbose = true) {
			client.verbose = verbose;
			return this;
		}
		Response oauth(in string consumerToken, in string consumerSecret, in string token, in string tokenSecret) {
			import std.digest.sha, std.base64, std.conv, std.random, std.datetime, std.string, hmac;
			oAuthParams = OAuthParams(consumerToken, consumerSecret, token, tokenSecret);
			string[string] params;
			auto copy_url = new URL(url.toString(false), url.Params);
			params["oauth_consumer_key"] = copy_url.Params["oauth_consumer_key"] = oAuthParams.consumerToken;
			params["oauth_token"] = copy_url.Params["oauth_token"] = oAuthParams.token;
			params["oauth_nonce"] = copy_url.Params["oauth_nonce"] = to!string(uniform(uint.min, uint.max)) ~ to!string(Clock.currTime().stdTime);
			//params["oauth_nonce"] = copy_url.Params["oauth_nonce"] = "1771511773635420822306363698";
			params["oauth_signature_method"] = copy_url.Params["oauth_signature_method"] = "HMAC-SHA1";
			params["oauth_timestamp"] = copy_url.Params["oauth_timestamp"] = to!string(Clock.currTime().toUTC().toUnixTime());
			//params["oauth_timestamp"] = copy_url.Params["oauth_timestamp"] = "1406485430";
			params["oauth_version"] = copy_url.Params["oauth_version"] = "1.0";
			string signature = [std.uri.encodeComponent(oAuthParams.consumerSecret), std.uri.encodeComponent(oAuthParams.tokenSecret)].join("&");
			//writeln(signature, "\n", [std.uri.encodeComponent(text(method).toUpper()), std.uri.encodeComponent(copy_url.str), std.uri.encodeComponent(copy_url.paramString)].join("&"));
			params["oauth_signature"] = Base64.encode(HMAC!SHA1(signature, std.uri.encodeComponent(text(method).toUpper())~"&"~std.uri.encodeComponent(copy_url.toString(false))~"&"~std.uri.encodeComponent(copy_url.paramString)));
			params["realm"] = "";

			string[] authString;
			foreach (k,v; params)
				authString ~= format(`%s="%s"`, k, std.uri.encodeComponent(v));
			Log(authString.join(",\n"));
			Log(format("Adding header: Authorization: %s", "OAuth " ~ authString.join(", ")));
			client.addRequestHeader("Authorization", "OAuth " ~ authString.join(", "));
			return this;
		}
		Response md5(string hash) {
			import std.string : toUpper;
			MD5hash = hash.toUpper();
			return this;
		}
		Response sha1(string hash) {
			import std.string : toUpper;
			SHA1hash = hash.toUpper();
			return this;
		}
		string md5() {
			import std.digest.md;
			if (!fetched)
				return "";
			return getHash!MD5;
		}
		string sha1() {
			import std.digest.sha;
			if (!fetched)
				return "";
			return getHash!SHA1;
		}
		private string getHash(Hash)() if(std.digest.sha.isDigest!Hash) {
			import std.digest.sha : toHexString, Order, LetterCase;
			Hash hash;
			hash.start();
			hash.put(_content);
			return toHexString!(Order.increasing, LetterCase.upper)(hash.finish());
		}
		@property string content() {
			if (!fetched)
				fetchContent(false);
			return cast(string)_content;
		}
		@property Json json() {
			import std.string : lastIndexOf;
			import json;
			auto a = content[0] == '{' ? lastIndexOf(content, '}') : content.length-1;
			//if (a == -1)
			//	a = content.length-1;
			auto fixedContent = content[0..a+1]; //temporary hack
			return parseJsonString(fixedContent);
		}
		@property Document dom() {
			return new Document(content);
		}
		void perform() {
			if (!fetched)
				fetchContent(false);
		}
		@property string[string] headers() {
			if (!fetched)
				fetchContent(true);
			return _headers;
		}
		private void fetchContent(bool ignoreStatus = false) {
			import std.digest.sha : toHexString;
			import std.string : format;
			import std.base64, std.conv : to;
			scope (exit) {
				client.onReceiveHeader = null;
    			client.onReceiveStatusLine = null;
				client.onSend = null;
				client.handle.onSeek = null;
			}
			assert(maxTries > 0, "Max tries set to zero?");
			Log("Beginning Response request");
			client.contentLength = contentLength;
			bool stopWriting = false;
			if (onReceive is null)
				client.onReceive = (ubyte[] data) {
					if (!stopWriting)
				    	_content ~= data;
				    return data.length;
				};
			else 
				client.onReceive = onReceive;
			client.handle.onSeek = onSeek;
			client.onSend = onSend;
			client.onReceiveHeader = (in char[] key, in char[] value) {
				if (auto v = key in _headers) {
						*v ~= ", ";
						*v ~= value;
				    } else
						_headers[key] = value.idup;
			};
			client.onReceiveStatusLine = (CurlHTTP.StatusLine line) { statusCode = line.code; };
			//assert((client.method == CurlHTTP.Method.post) && (onSend is null), "POST Request missing onSend callback");
			uint redirectCount = 0;
			Exception lastException;
			foreach (trial; 0..maxTries) {
				stopWriting = false;
				client.url = url.toString();
				client.method = method;
				Log(format("Fetching %s with method %s from %s (%s)\nOther headers: %s", url, client.method, url.Hostname, url.Protocol, this.outer.headers));
				try {
					_content = [];
					_headers = null;
					client.perform();
					stopWriting = true;
					if ("content-md5" in _headers) {
						scope(exit) fetched = false;
						fetched = true;
						if (md5 != toHexString(Base64.decode(_headers["content-md5"])))
							throw new HashException("MD5", md5, toHexString(Base64.decode(_headers["content-md5"])));
					}
					if ("content-length" in _headers) {
						if (_content.length != _headers["content-length"].to!size_t)
							throw new HTTPException("Content length mismatched");
					}
					if (statusCode >= 300) {
						if (!ignoreStatus) 
							throw new StatusException(statusCode);
					} else
						fetched = true;
					if (checkNoContent && (_content.length == 0))
						throw new HTTPException("No data received");
					if ((MD5hash != "") && (md5 != MD5hash))
						throw new HashException("MD5", md5, MD5hash);
					if ((SHA1hash != "") && (sha1 != SHA1hash))
						throw new HashException("SHA1", sha1, SHA1hash);
					Log("Success!");
					return;
				} catch (CurlException e) {
					lastException = e;
					Log(e.toString());
				} catch (StatusException e) {
					Log(format("HTTP %s error", statusCode));
					switch (statusCode) {
						case 301, 302, 303, 307, 308:
							if (redirectCount++ >= 5)
								throw new StatusException(statusCode);
							url = url.absoluteURL(_headers["location"]);
							if ((statusCode == 301) || (statusCode == 302) || (statusCode == 303))
								method = CurlHTTP.Method.get;
							break;
						case 500, 502, 503, 504:
							break;
						default: 
							throw new StatusException(statusCode);
					}
					lastException = e;
				} catch (HTTPException e) {
					lastException = e;
					Log(e.toString());
				}
			}
			throw lastException;
		}
	}
}
class URL {
	string[string] Params;
	enum Proto { Unknown, HTTP, HTTPS, Same, None};
	Proto Protocol;
	string Hostname;
	string Path;
	this(in string str, in string[string] inParams = null) {
		import std.array : replace;
		import std.algorithm : find;
		import std.string : toLower, split, join;
		Log("Creating URL from string: " ~ str);
		//Get protocol
		if (str.length >= 6) {
			if (str[0..5].toLower() == "http:")
				Protocol = Proto.HTTP;
			else if (str[0..5].toLower() == "https")
				Protocol = Proto.HTTPS;
		} 
		if ((str.length >= 2) && (str[0..2] == "//"))
			Protocol = Proto.Same;
		else if ((str.length >= 1) && str[0] == '/')
			Protocol = Proto.None;

		//Get Hostname
		auto splitURL = str.split("/");
		if (splitURL.length > 0) {
			if (Protocol == Proto.Unknown)
				Hostname = splitURL[0].toLower();
			else if (Protocol == Proto.None)
				Hostname = splitURL[1].toLower();
			else
				Hostname = splitURL[2].toLower();
			//Get Path
			if (Protocol == Proto.Unknown)
				Path = splitURL[0..$].join("/");
			else if (Protocol == Proto.None)
				Path = splitURL[1..$].join("/");
			else
				Path = splitURL[3..$].join("/");
			
			if (Path.length == 0)
				Path = "/";

			if (Path[0] != '/')
				Path = "/"~Path;
			auto existingParameters = Path.find("?");
			if (existingParameters.length > 0) {
				foreach (arg; existingParameters[1..$].split("&")) {
					auto splitArg = arg.split("=");
					if (splitArg.length > 1)
						Params[std.uri.decode(splitArg[0].replace("+", " "))] = std.uri.decode(splitArg[1].replace("+", " "));
					else
						Params[std.uri.decode(arg.replace("+", " "))] = "";
				}
				Path = Path.split("?")[0];
			}
		}
		foreach (k,v; inParams)
			Params[k] = v;
	}
	this(Proto protocol, string hostname, string path, string[string] inParams = null) @safe {
		Protocol = protocol;
		Hostname = hostname;
		Path = path;
		Params = inParams;
	}
	this(in Proto protocol, in string hostname, in string path, in string[string] inParams = null) {
		Protocol = protocol;
		Hostname = hostname;
		Path = path;
		Params = cast(typeof(Params))inParams.dup();
	}
	@property string Filename() nothrow const {
		import std.string : split;
		return Path.split("/")[$-1];
	}
	@property string paramString() nothrow const {
		import std.uri;
		import std.string : format, join;
		if (Params == null) return "";
		scope(failure) return "";
		string[] parameterPrintable;
		foreach (parameter, value; Params)
			if (value == "")
				parameterPrintable ~= parameter.encode();
			else
				parameterPrintable ~= format("%s=%s", parameter.encode(), value.encode());
		return "?"~parameterPrintable.join("&");
	}
	URL absoluteURL(in string urlB, in string[string] params = null) const {
		import std.string : split, join;
		auto newURL = new URL(urlB, params);
		if (urlB == "")
			return new URL(Protocol, Hostname, Path, Params);
		if (toString() == urlB)
			return new URL(Protocol, Hostname, Path, Params);
		if ((newURL.Protocol == Proto.HTTP) || (newURL.Protocol == Proto.HTTPS))
			return newURL;
		if ((urlB[0] == '/') && ((urlB.length == 1) || (urlB[1] != '/')))
			return new URL(Protocol, Hostname, newURL.Path, newURL.Params);
		if (newURL.Protocol == Proto.Same) {
			return new URL(Protocol, newURL.Hostname, newURL.Path, newURL.Params);
		}
		if (urlB == ".")
			return new URL(Protocol, Hostname, Path, Params);
		if (urlB == "..")
			return new URL(Protocol, Hostname, Path.split("/")[0..$-1].join("/"), Params);
		return new URL(Protocol, Hostname, Path ~ "/" ~ urlB, Params);
	}
	override string toString() const {
		auto v = toString(true);
	//	writeln(v);
		return v;
	}
	string toString(bool includeParameters) const {
		string output;
		if (Protocol == Proto.HTTPS)
			output ~= "https://" ~ Hostname;
		else if (Protocol == Proto.HTTP)
			output ~= "http://" ~ Hostname;
		else if (Protocol == Proto.None)
			output ~= "/" ~ Hostname;
		else if (Protocol == Proto.Same)
			output ~= "//" ~ Hostname;
		output ~= Path;
		if (includeParameters)
			output ~= paramString();
		return output;
	}
}
deprecated private string parametersToURLString(string url, in string[string] parameters) {
	import std.uri;
	import std.algorithm : canFind;
	import std.string : split, format, join;
	if (parameters == null) return url;
	if (parameters.length > 0) {
		string[] parameterPrintable;
		foreach (parameter, value; parameters)
			parameterPrintable ~= format("%s=%s", parameter.encode(), value.encode());
		return url ~ (url.split("/")[$-1].canFind("?") ? "&" : "?") ~ parameterPrintable.join("&");
	}
	return url;
}
class StatusException : HTTPException { 
	public int code;
	this(int errorCode, string file = __FILE__, size_t line = __LINE__) {
		import std.string : format;
		code = errorCode;
		super(format("Error %d fetching URL", errorCode), file, line);
	}
}
class HashException : HTTPException {
	this(string hashType, string badHash, string goodHash, string file = __FILE__, size_t line = __LINE__) in {
		assert(goodHash != badHash, "Good hash and mismatched hash match!");
	} body {
		import std.string : format;
		super(format("Hash mismatch (%s): %s != %s", hashType, badHash, goodHash), file, line);
	}
}
class HTTPException : Exception {
	this(string msg, string file = __FILE__, size_t line = __LINE__) {
		super(msg, file, line);
	}
}
unittest {
	assert(new URL("http://url.example").Protocol == URL.Proto.HTTP, "HTTP detection failure");
	assert(new URL("https://url.example").Protocol == URL.Proto.HTTPS, "HTTPS detection failure");
	assert(new URL("url.example").Protocol == URL.Proto.Unknown, "No-protocol detection failure");
	assert(new URL("HTTP://URL.EXAMPLE").Protocol == URL.Proto.HTTP, "HTTP caps detection failure");
	assert(new URL("HTTPS://URL.EXAMPLE").Protocol == URL.Proto.HTTPS, "HTTPS caps detection failure");
	assert(new URL("URL.EXAMPLE").Protocol == URL.Proto.Unknown, "No-protocol caps detection failure");
}
unittest {
	assert(new URL("http://url.example").Hostname == "url.example", "HTTP hostname detection failure");
	assert(new URL("https://url.example").Hostname == "url.example", "HTTPS hostname detection failure");
	assert(new URL("url.example").Hostname == "url.example", "No-protocol hostname detection failure");
	assert(new URL("http://url.example/dir").Hostname == "url.example", "HTTP hostname detection failure");
	assert(new URL("HTTP://URL.EXAMPLE").Hostname == "url.example", "HTTP caps hostname detection failure");
	assert(new URL("HTTPS://URL.EXAMPLE").Hostname == "url.example", "HTTPS caps hostname detection failure");
	assert(new URL("URL.EXAMPLE").Hostname == "url.example", "No-protocol caps hostname detection failure");
	assert(new URL("http://URL.EXAMPLE/DIR").Hostname == "url.example", "path+caps hostname detection failure");
}
unittest {
	assert(new URL("http://url.example").absoluteURL("https://url.example").toString() == "https://url.example/", "Switching protocol failure");
	assert(new URL("http://url.example").absoluteURL("http://url.example").toString() == "http://url.example/", "Identical URL failure");
	assert(new URL("http://url.example").absoluteURL("/something").toString() == "http://url.example/something", "Root-relative URL failure");
	assert(new URL("http://url.example").absoluteURL("//different.example").toString() == "http://different.example/", "Same-protocol relative URL failure");
	assert(new URL("http://url.example/dir").absoluteURL(".").toString() == "http://url.example/dir", "Dot URL failure");
	assert(new URL("http://url.example/dir").absoluteURL("..").toString() == "http://url.example", "Relative parent URL failure");
	assert(new URL("http://url.example/dir").absoluteURL("/different").toString() == "http://url.example/different", "Root-relative (w/dir) URL failure");
	assert(new URL("http://url.example/dir").absoluteURL("different").toString() == "http://url.example/dir/different", "cwd-relative (w/dir) URL failure");
}
unittest {
	assert(new URL("").Params is null, "URIArguments: Empty string failure");
	assert(new URL("http://url.example/?hello=world").Params == ["hello":"world"], "URIArguments: Simple test failure");
	assert(new URL("http://url.example/?hello=world+butt").Params == ["hello":"world butt"], "URIArguments: Plus as space in value failure");
	assert(new URL("http://url.example/?hello+butt=world").Params == ["hello butt":"world"], "URIArguments: Plus as space in key failure");
	assert(new URL("http://url.example/?hello=world%20butt").Params == ["hello":"world butt"], "URIArguments: URL decoding in value failure");
	assert(new URL("http://url.example/?hello%20butt=world").Params == ["hello butt":"world"], "URIArguments: URL decoding in key failure");
	assert(new URL("http://url.example/?hello").Params == ["hello":""], "URIArguments: Key only failure");
	assert(new URL("http://url.example/?hello=").Params == ["hello":""], "URIArguments: Empty value failure");
	assert(new URL("http://url.example/?hello+").Params == ["hello ":""], "URIArguments: Key only with plus sign failure");
	assert(new URL("http://url.example/?hello+=").Params == ["hello ":""], "URIArguments: Empty value with plus sign failure");
}
unittest {
	assert(new URL("http://url.example/?test", ["test2": "value"]).Params == ["test":"", "test2":"value"], "Merged parameters failure");
}
unittest {
	import std.exception, std.file;
	auto tURL = new HTTP("http://misc.herringway.pw", ["Referer":"http://sg.test"]);
	assert(tURL.get("/.test.php").content == "GET");
	assert(tURL.get("/.test.php").status == 200, "200 status undetected");
	assert(tURL.get("/.test.php?301").content == "GET");
	assert(tURL.get("/.test.php?301").status == 301, "301 error undetected");
	assert(tURL.get("/.test.php?302").content == "GET");
	assert(tURL.get("/.test.php?302").status == 302, "302 error undetected");
	assert(tURL.get("/.test.php?303").content == "GET");
	assert(tURL.get("/.test.php?303").status == 303, "303 error undetected");
	assert(tURL.get("/.test.php?307").content == "GET");
	assert(tURL.get("/.test.php?307").status == 307, "307 error undetected");
	assert(tURL.get("/.test.php?308").content == "GET");
	assertThrown(tURL.get("/.test.php?403").perform());
	assert(tURL.get("/.test.php?403").status == 403, "403 error undetected");
	assertThrown(tURL.get("/.test.php?404").perform());
	assert(tURL.get("/.test.php?404").status == 404, "404 error undetected");
	assertThrown(tURL.get("/.test.php?500").perform());
	assert(tURL.get("/.test.php?500").status == 500, "500 error undetected");
	assertThrown(tURL.get("/.test.php").md5("BAD").perform(), "Erroneous MD5 failure");
	assertThrown(tURL.get("/.test.php").sha1("BAD").perform(), "Erroneous MD5 failure");
	assert(tURL.post("/.test.php", "beep").content == "beep", "POST failed");
	auto a1 = tURL.get("/whack.gif");
	scope(exit) if (exists("whack.gif")) remove("whack.gif");
	scope(exit) if (exists("whack2.gif")) remove("whack2.gif");
	a1.saveTo("whack.gif");
	a1.saveTo("whack2.gif");
	auto resp1 = tURL.post("/.test.php?1", "beep1");
	auto resp2 = tURL.post("/.test.php?2", "beep2");
	assert(resp2.content == "beep2");
	assert(resp2.content == "beep2");
	assert(resp1.content == "beep1");
}