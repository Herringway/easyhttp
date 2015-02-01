module httpinterface;

public import fs;
public import stdx.data.json : JSONValue;
public deprecated alias Json = JSONValue;
public import arsd.dom : Document, Element;

public uint defaultMaxTries = 5;
version(Have_loggins) private import loggins;
else {
	void log(T...)(string fmt, T params) {
		import std.stdio : writefln;
		writefln(fmt, params);
	}
	alias LogTrace = log;
	alias LogDebugV = log;
	alias LogDebug = log;
	alias LogDiagnostic = log;
	alias LogInfo = log;
	alias LogError = log;
}
alias useHTTPS = bool;
alias URLParameters = string[string];
alias URLHeaders = string[string];
alias URLString = string;
alias POSTData = string;
alias POSTParams = string[string];

public string[] ExtraCurlCertSearchPaths = [];
HTTPFactory httpfactory;
static this() {
	httpfactory = new HTTPFactory;
}
class HTTPFactory {
	import std.typecons : Nullable;
	public string CookieJar;
	public uint RetryCount = 5;
	private HTTP[string] activeHTTP;
	private Nullable!string certPath;
	this() @safe {
		import std.file : exists;
		string[] caCertSearchPaths = ExtraCurlCertSearchPaths;
		version(Windows) caCertSearchPaths ~= "./curl-ca-bundle.crt";
		version(Linux) caCertSearchPaths ~= ["/usr/share/ca-certificates"];
		version(FreeBSD) caCertSearchPaths ~= ["/usr/local/share/certs/ca-root-nss.crt"];
		foreach (path; caCertSearchPaths)
			if (path.exists) {
				certPath = path;
				LogDebugV("Found certs at %s", path);
				break;
			}
	}
	HTTP spawn(in URL inURL, URLHeaders reqHeaders = URLHeaders.init) {
		LogDebugV("Spawning...%s", inURL);
		if (inURL.Hostname !in activeHTTP) {
			LogDebugV("Spawning new HTTP instance for %s (%s)", inURL.toString(), reqHeaders);
			activeHTTP[inURL.Hostname] = new HTTP(inURL, reqHeaders);
			activeHTTP[inURL.Hostname].CookieJar = CookieJar;
			if (!certPath.isNull)
				activeHTTP[inURL.Hostname].Certificates = certPath;
		} else
			LogDebugV("Reusing HTTP instance for %s (%s)", inURL.toString(), reqHeaders);
		return activeHTTP[inURL.Hostname];
	}
	HTTP spawn(in string inURL, URLHeaders reqHeaders = URLHeaders.init) {
		return spawn(URL(inURL), reqHeaders);
	}
}
class HTTP {
	import std.net.curl : CurlException, CurlHTTP = HTTP;
	public const(URL) url;

	public uint retryCount = 5;

	private CurlHTTP HTTPClient;
	private string[string] _headers;
	private string _cookiepath;
	private bool peerVerification = false;
	this(in string inURL, in string[string] reqHeaders = null) @trusted {
		this(URL(inURL), reqHeaders);
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
	this(in string hostname, in useHTTPS https, in string[string] reqHeaders) {
		this("http"~(https ? "s" : "")~"://"~hostname, reqHeaders);
	}
	~this() nothrow {
		scope (failure) return;
		HTTPClient.shutdown();
	}
	void AddHeader(string key, string value) {
		HTTPClient.addRequestHeader(key, value);
		_headers[key] = value;
	}
	@property string[string] headers(in string[string] newHeaders) @trusted {
		LogDebugV("Resetting headers: %s => []", _headers);
		HTTPClient.clearRequestHeaders();
		_headers = null;
		foreach (key, value; newHeaders)
			AddHeader(key, value);
		LogDebugV("Setting headers: %s", _headers);
		return _headers;
	}
	@property string[string] headers() @safe {
		return _headers;
	}
	@property string CookieJar(FileSystemPath path) @trusted in {
		import std.path;
		import std.file;
		assert(dirName(path).isDir, dirName(path)~" is not a directory!");
	} body {
		_cookiepath = path;
		HTTPClient.setCookieJar(path);
		return path;
	}
	@property string CookieJar() @safe {
		return _cookiepath;
	}
	string Certificates(FileSystemPath path) @trusted {
		import std.exception : enforce;
		import std.file : exists;
		enforce(path.exists(), "Certificate path not found");
		HTTPClient.caInfo = path;
		HTTPClient.verifyPeer = true;
		peerVerification = true;
		return path;
	}
	Response get(URL inURL) {
		auto output = Response(HTTPClient, url.absoluteURL(inURL), peerVerification);
		output.outHeaders = _headers;
		output.method = CurlHTTP.Method.get;
		output.onReceive = null;
		output.maxTries = retryCount;
		LogDebugV("Spawning GET Response for host %s, path %s", output.url.Hostname, output.url.Path);
		return output;
	}
	Response post(URL url, POSTParams data) {
		return post(url.Path, data, url.Params);
	}
	auto post(URL url, POSTData data) {
		return post(url.Path, data, url.Params);
	}
	auto get(in string path, URLParameters params = URLParameters.init) @trusted {
		return get(URL(url.Protocol, url.Hostname, path, params));
	}
	auto post(string path, POSTData inData, URLParameters params = URLParameters.init) @trusted {
		import std.string : representation;
		import std.algorithm : min;
		import etc.c.curl : CurlSeekPos, CurlSeek;
		auto output = Response(HTTPClient, URL(url.Protocol, url.Hostname, path, params), peerVerification);
		output.outHeaders = _headers;
		output.method = CurlHTTP.Method.post;
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
			LogDebugV("POSTING %s", remainingData[0..minLen]);
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
		LogDebugV("Spawning POST Response for host %s, path %s", output.url.Hostname, output.url.Path);
		return output;
	}
	auto post(string path, POSTParams data, URLParameters params = URLParameters.init) {
		import std.uri : encode;
		import std.string : join;
		string[] newdata;
		foreach (key, val; data)
			newdata ~= encode(key) ~ "=" ~ encode(val);
		return post(path, newdata.join("&"), params);
	}
	Response post(string path, in POSTParams data, in URLParameters params = URLParameters.init) {
		return post(path, data.dup, params.dup);
	}
	override string toString() {
		return url.toString();
	}
	struct Response {
		struct Hash {
			Nullable!string hash;
			Nullable!string original;
			alias hash this;
			this(string inHash) pure @safe {
				original = inHash;
			}
		}
		import std.typecons : Nullable;
		import core.time : Duration, dur;
		import etc.c.curl : CurlSeekPos, CurlSeek;
		import std.digest.sha : isDigest;
		private struct OAuthParams {
			string consumerToken;
			string consumerSecret;
			string token;
			string tokenSecret;
		}
		string bearerToken;
		const(ubyte)[] _content;
		string[string] _headers;
		string[string] _sendHeaders;
		private Nullable!size_t sizeExpected;
		private CurlHTTP* client;
		private bool fetched = false;
		private bool checkNoContent = false;
		uint maxTries;
		Duration timeout = dur!"minutes"(5);
		URL url;
		size_t delegate(ubyte[]) onReceive;
		CurlSeek delegate(long offset, CurlSeekPos mode) onSeek;
		size_t delegate(void[] buf) onSend;
		uint contentLength;
		CurlHTTP.Method method;
		Hash[string] hashes;
		private OAuthParams oAuthParams;
		bool ignoreHostCert = false;
		bool verifyPeer = true;
		ushort statusCode;
		@disable this();
		invariant() {
			assert((url.Protocol != Proto.Unknown) && (url.Protocol != Proto.None) && (url.Protocol != Proto.Same), "No protocol specified in URL");
			assert(!(cast()*client).isStopped(), "Dead curl instance!");
		}
		private this(ref CurlHTTP inClient, URL initial, bool peerVerification) {
			if (initial.Protocol == Proto.HTTPS)
				LogDiagnostic(!peerVerification, "Peer verification disabled!");
			verifyPeer = peerVerification;
			client = &inClient;
			url = initial;
		}
		void reset() nothrow pure @safe {
			_content = [];
			_headers = null;
			fetched = false;
		}
		@property ref string[string] outHeaders() {
			return _sendHeaders;
		}
		@property string filename() nothrow const pure {
			return url.Filename;
		}
		@property bool isValid() nothrow const {
			scope(failure) return false;
			return !(cast()*client).isStopped();
		}
		struct SavedFileInformation {
			string path;
		}
		SavedFileInformation saveTo(string dest, bool overwrite = true) {
			auto output = SavedFileInformation();
			import std.file : exists, mkdirRecurse;
			import std.path : dirName;
			if (!overwrite)
				while (exists(dest))
					dest = duplicateName(dest);
			output.path = dest;
			if (!exists(dest.dirName()))
				mkdirRecurse(dest.dirName());
			dest = dest.fixPath();
			version(Windows) {
				import std.stream : File, FileMode;
				auto outFile = new File(dest, FileMode.OutNew);
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
				import std.stdio : File;
				auto outFile = File(dest, "wb");
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
			return output;
		}
		@property ushort status() {
			if (!fetched)
				fetchContent(true);
			return statusCode;
		}
		auto guaranteeData(bool val = true) @safe pure nothrow {
			checkNoContent = val;
			return this;
		}
		auto setVerbosity(bool verbose = true) {
			client.verbose = verbose;
			return this;
		}
		auto AddHeader(string key, string val) {
			_sendHeaders[key] = val;
			return this;
		}
		enum OAuthMethod {Header, URL, Form };
		auto OAuthBearer(in string token, OAuthMethod method = OAuthMethod.Header) {
			bearerToken = token;
			AddHeader("Authorization", "Bearer "~token);
			return this;
		}
		auto oauth(in string consumerToken, in string consumerSecret, in string token, in string tokenSecret) {
			import std.digest.sha, std.base64, std.conv, std.random, std.datetime, std.string, hmac;
			oAuthParams = OAuthParams(consumerToken, consumerSecret, token, tokenSecret);
			string[string] params;
			auto copy_url = URL(url.toString(false), url.Params);
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
			LogDebugV("Oauth: %(%s,\n%)", authString);
			LogDebugV("Adding header: Authorization: %s", "OAuth " ~ authString.join(", "));
			AddHeader("Authorization", "OAuth " ~ authString.join(", "));
			return this;
		}
		auto expectedSize(size_t size) {
			sizeExpected = size;
			return this;
		}
		import std.digest.md : MD5;
		import std.digest.sha : SHA1, SHA256, SHA384, SHA512;
		import std.digest.crc : CRC32;
		alias md5 = hash!MD5;
		alias sha1 = hash!SHA1;
		alias sha256 = hash!SHA256;
		alias sha384 = hash!SHA384;
		alias sha512 = hash!SHA512;
		deprecated alias crc32 = hash!CRC32;
		template hash(HashMethod) {
			auto hash(string hash) @safe pure in {
				import std.string : removechars;
				assert(hash.removechars("[0-9a-fA-F]") == [], "Non-hexadecimal characters found in hash");
			} body {
				import std.digest.digest : digestLength;
				import std.string : toUpper, format;
				import std.exception : enforce;
				enforce(hash.length == 2*digestLength!HashMethod, format("%s hash strings must be %s characters in length", HashMethod.stringof, 2*digestLength!HashMethod));
				hashes[HashMethod.stringof] = Hash(hash.toUpper());
				return this;
			}
			public Hash hash(bool skipCompleteCheck = false) pure nothrow {
				if (HashMethod.stringof !in hashes)
					hashes[HashMethod.stringof] = Hash();
				if (skipCompleteCheck || fetched)
					hashes[HashMethod.stringof].hash = getHash!HashMethod;
				return hashes[HashMethod.stringof];
			}
			public Hash hash(bool skipCompleteCheck = false) pure nothrow const {
				Hash output;
				if (HashMethod.stringof in hashes)
					output = hashes[HashMethod.stringof];
				if (skipCompleteCheck || fetched)
					output.hash = getHash!HashMethod;
				return output;
			}
		}
		private string getHash(HashMethod)() pure nothrow const if(isDigest!HashMethod) {
			import std.digest.digest : toHexString, Order, LetterCase, makeDigest;
			auto hash = makeDigest!HashMethod;
			hash.put(_content);
			return hash.finish().toHexString!(Order.increasing, LetterCase.upper);
		}
		auto IgnoreHostCertificate(bool val = true) @safe pure nothrow {
			ignoreHostCert = val;
			return this;
		}
		auto DisablePeerVerification(bool val = true) @safe pure nothrow {
			verifyPeer = val;
			return this;
		}
		auto SetMaxTries(uint max) @safe pure nothrow {
			maxTries = max;
			return this;
		}
		auto SetTimeout(Duration time) @safe pure nothrow {
			timeout = time;
			return this;
		}
		@property string content() {
			if (!fetched)
				fetchContent(false);
			return cast(string)_content;
		}
		@property JSONValue json() {
			import std.string : lastIndexOf;
			import stdx.data.json;
			auto a = content[0] == '{' ? lastIndexOf(content, '}') : content.length-1;
			auto fixedContent = content[0..a+1]; //temporary hack
			return parseJSONValue(fixedContent);
		}
		@property Document dom() {
			return new Document(content);
		}
		void perform(bool ignoreStatus = false) {
			if (!fetched)
				fetchContent(ignoreStatus);
		}
		@property string[string] headers() {
			if (!fetched)
				fetchContent(true);
			return _headers;
		}
		private void fetchContent(bool ignoreStatus = false) in {
			assert(maxTries > 0, "Max tries set to zero?");
		} body {
			debug LogTrace("Fetching content");
			import std.digest.sha : toHexString;
			import std.exception : enforce;
			import std.base64, std.conv : to;
			scope (exit) {
				client.onReceiveHeader = null;
    			client.onReceiveStatusLine = null;
				client.onSend = null;
				client.handle.onSeek = null;
			}
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
			client.connectTimeout(timeout);
			client.verifyPeer(!verifyPeer);
			client.verifyHost(!ignoreHostCert);
			client.onReceiveStatusLine = (CurlHTTP.StatusLine line) { statusCode = line.code; };
			debug LogTrace("Completed setting curl parameters");
			uint redirectCount = 0;
			Exception lastException;
			client.clearRequestHeaders();
			foreach (key, value; _sendHeaders)
				client.addRequestHeader(key, value);
			foreach (trial; 0..maxTries) {
				stopWriting = false;
				client.url = url.toString();
				client.method = method;
				LogDebugV("Fetching %s with method %s from %s (%s)\nOther headers: %s", url, client.method, url.Hostname, url.Protocol, _sendHeaders);
				try {
					_content = [];
					_headers = null;
					client.perform();
					stopWriting = true;
					if ("content-md5" in _headers)
						enforce(md5(true) == toHexString(Base64.decode(_headers["content-md5"])), new HashException("MD5", md5(true), toHexString(Base64.decode(_headers["content-md5"]))));
					if ("content-length" in _headers)
						enforce(_content.length == _headers["content-length"].to!size_t, new HTTPException("Content length mismatched"));
					if (!sizeExpected.isNull)
						enforce(_content.length == sizeExpected, new HTTPException("Size of data mismatched expected size"));
					if (checkNoContent)
						enforce(_content.length > 0, new HTTPException("No data received"));
					if (!ignoreStatus) 
						enforce(statusCode < 300, new StatusException(statusCode));
					if (!md5(true).original.isNull())
						enforce(md5.original == md5.hash, new HashException("MD5", md5.original, md5.hash));
					if (!sha1(true).original.isNull())
						enforce(sha1.original == sha1.hash, new HashException("SHA1", sha1.original, sha1.hash));
					fetched = true;
					return;
				} catch (CurlException e) {
					lastException = e;
					LogDebugV("%s", e);
				} catch (StatusException e) {
					LogDebugV("HTTP %s error", statusCode);
					switch (statusCode) {
						case 301, 302, 303, 307, 308:
							enforce(redirectCount++ < 5, e);
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
					LogDebugV("%s", e);
				}
			}
			throw lastException;
		}
	}
}
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
@property auto NullResponse() {
	return httpfactory.spawn("http://localhost").get("http://localhost");
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
	this(int errorCode, string file = __FILE__, size_t line = __LINE__) @safe pure {
		import std.string : format;
		code = errorCode;
		super(format("Error %d fetching URL", errorCode), file, line);
	}
}
class HashException : HTTPException {
	this(string hashType, string badHash, string goodHash, string file = __FILE__, size_t line = __LINE__) @safe pure in {
		assert(goodHash != badHash, "Good hash and mismatched hash match!");
	} body {
		import std.string : format;
		super(format("Hash mismatch (%s): %s != %s", hashType, badHash, goodHash), file, line);
	}
}
class HTTPException : Exception {
	this(string msg, string file = __FILE__, size_t line = __LINE__) @safe nothrow pure {
		super(msg, file, line);
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
	assert(URL("http://url.example").absoluteURL(URL("https://url.example")).toString() == "https://url.example", "Switching protocol (class) failure");
	assert(URL("http://url.example").absoluteURL("http://url.example").toString() == "http://url.example", "Identical URL (string) failure");
	assert(URL("http://url.example").absoluteURL(URL("http://url.example")).toString() == "http://url.example", "Identical URL (class) failure");
	assert(URL("http://url.example").absoluteURL("/something").toString() == "http://url.example/something", "Root-relative URL (string) failure");
	assert(URL("http://url.example").absoluteURL(URL("/something")).toString() == "http://url.example/something", "Root-relative URL (class) failure");
	assert(URL("http://url.example").absoluteURL("//different.example").toString() == "http://different.example", "Same-protocol relative URL (string) failure");
	assert(URL("http://url.example").absoluteURL(URL("//different.example")).toString() == "http://different.example", "Same-protocol relative URL (class) failure");
	assert(URL("http://url.example/dir").absoluteURL(".").toString() == "http://url.example/dir", "Dot URL (string) failure");
	assert(URL("http://url.example/dir").absoluteURL(URL(".")).toString() == "http://url.example/dir", "Dot URL (class) failure");
	assert(URL("http://url.example/dir").absoluteURL("..").toString() == "http://url.example", "Relative parent URL (string) failure");
	assert(URL("http://url.example/dir").absoluteURL(URL("..")).toString() == "http://url.example", "Relative parent URL (class) failure");
	assert(URL("http://url.example/dir").absoluteURL("/different").toString() == "http://url.example/different", "Root-relative (w/dir) URL (string) failure");
	assert(URL("http://url.example/dir").absoluteURL(URL("/different")).toString() == "http://url.example/different", "Root-relative (w/dir) URL (class) failure");
	assert(URL("http://url.example/dir").absoluteURL("different").toString() == "http://url.example/dir/different", "cwd-relative (w/dir) URL (string) failure");
	assert(URL("http://url.example/dir").absoluteURL(URL("different")).toString() == "http://url.example/dir/different", "cwd-relative (w/dir) URL (class) failure");
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
unittest {
	import std.exception;
	auto httpinstance = httpfactory.spawn("http://misc.herringway.pw");
	assertNotThrown(httpinstance.get("/.test.php").md5("7528035a93ee69cedb1dbddb2f0bfcc8").status);
	assertNotThrown(httpinstance.get("/.test.php").md5("7528035A93EE69CEDB1DBDDB2F0BFCC8").status);
	assertNotThrown(httpinstance.get("/.test.php").sha1("f030bbbd32966cde41037b98a8849c46b76e4bc1").status);
	assertNotThrown(httpinstance.get("/.test.php").sha1("F030BBBD32966CDE41037B98A8849C46B76E4BC1").status);
	assertThrown(httpinstance.get("/.test.php").md5("7528035A93EE69CEDB1DBDDB2F0BFCC9").status);
	assertThrown(httpinstance.get("/.test.php").md5(""));
	assertThrown(httpinstance.get("/.test.php").sha1("F030BBBD32966CDE41037B98A8849C46B76E4BC2").status);
}
unittest {
	import std.exception;
	auto httpinstance = httpfactory.spawn("http://misc.herringway.pw");
	assertNotThrown(httpinstance.get("/.test.php").expectedSize(3).status);
	assertThrown(httpinstance.get("/.test.php").expectedSize(4).status);
}
unittest {
	import std.exception;
	auto httpinstance = httpfactory.spawn("http://misc.herringway.pw");
	assertNotThrown(httpinstance.post("/.test.php", "hi").guaranteeData().status);
	assertThrown(httpinstance.post("/.test.php", "").guaranteeData().status);
}
unittest {
	import std.exception, std.file;
	auto tURL = httpfactory.spawn("http://misc.herringway.pw", ["Referer":"http://sg.test"]);
	assert(tURL.get("/.test.php").content == "GET", "GET string failure");
	assert(tURL.get(URL("/.test.php")).content == "GET", "GET URL failure");
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
	assert(tURL.post("/.test.php", "beep").content == "beep", "POST string failed");
	assert(tURL.post(URL("/.test.php"), "beep").content == "beep", "POST URL failed");

	assert(tURL.get("/.test.php?PRINTHEADER").AddHeader("echo", "hello world").content == "hello world", "adding header failed");

	auto a1 = tURL.get("/whack.gif");
	scope(exit) if (exists("whack.gif")) remove("whack.gif");
	scope(exit) if (exists("whack(2).gif")) remove("whack(2).gif");
	scope(exit) if (exists("whack2.gif")) remove("whack2.gif");
	a1.saveTo("whack.gif");
	assert(a1.saveTo("whack.gif", false).path == "whack(2).gif", "failure to rename file to avoid overwriting");
	a1.saveTo("whack2.gif");
	auto resp1 = tURL.post("/.test.php?1", "beep1");
	auto resp2 = tURL.post("/.test.php?2", "beep2");
	assert(resp2.content == "beep2");
	assert(resp2.content == "beep2");
	assert(resp1.content == "beep1");
}