module httpinterface;

public import fs, url;
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
alias POSTData = string;
alias POSTParams = string[string];

public string[] ExtraCurlCertSearchPaths = [];

enum HTTPStatus : ushort {
	//1xx - Informational
	Continue = 100,
	SwitchingProtocols = 101,
	Processing = 102,
	//2xx - Successful
	OK = 200,
	Created = 201,
	Accepted = 202,
	NonAuthoritative = 203,
	NoContent = 204,
	ResetContent = 205,
	PartialContent = 206,
	MultiStatus = 207,
	AlreadyReported = 208,
	IMUsed = 226,
	//3xx - Redirecting
	MultipleChoices = 300,
	MovedPermanently = 301,
	Found = 302,
	SeeOther = 303,
	NotModified = 304,
	UseProxy = 305,
	SwitchProxy = 306, //Not used anymore
	TemporaryRedirect = 307,
	PermanentRedirect = 308,
	//4xx - Client Error
	BadRequest = 400,
	Unauthorized = 401,
	PaymentRequired = 402,
	Forbidden = 403,
	NotFound = 404,
	MethodNotAllowed = 405,
	NotAcceptable = 406,
	ProxyAuthenticationRequired = 407,
	RequestTimeout = 408,
	Conflict = 409,
	Gone = 410,
	LengthRequired = 411,
	PreconditionFailed = 412,
	RequestEntityTooLarge = 413,
	RequestURITooLong = 414,
	UnsupportedMediaType = 415,
	RequestRangeNotSatisfiable = 416,
	ExpectationFailed = 417,
	ImATeapot = 418,
	AuthenticationTimeout = 419,
	MethodFailure = 420,
	EnhanceYourCalm = 420,
	MisdirectedRequest = 421,
	UnprocessableEntity = 422,
	Locked = 423,
	FailedDependency = 424,
	UpgradeRequired = 426,
	PreconditionRequired = 428,
	TooManyRequests = 429,
	RequestHeaderFieldsTooLarge = 431,
	LoginTimeout = 440,
	RetryWith = 449,
	BlockedByWindowsParentalControls = 450,
	UnavailableForLegalReasons = 451,
	//5xx - Server Error
	InternalServerError = 500,
	NotImplemented = 501,
	BadGateway = 502,
	ServiceUnavailable = 503,
	GatewayTimeout = 504,
	HTTPVersionNotSupported = 505,
	VariantAlsoNegotiates = 506,
	InsufficientStorage = 507,
	LoopDetected = 508,
	BandwidthLimitExceeded = 509,
	NotExtended = 510,
	NetworkAuthenticationRequired = 511
}
HTTPFactory httpfactory;
static this() {
	httpfactory = HTTPFactory();
}
struct HTTPFactory {
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
	auto get(T = string)(URL inURL) {
		auto output = Response!(T)(HTTPClient, url.absoluteURL(inURL), peerVerification);
		output.outHeaders = _headers;
		output.method = CurlHTTP.Method.get;
		output.onReceive = null;
		output.maxTries = retryCount;
		LogDebugV("Spawning GET Response for host %s, path %s", output.url.Hostname, output.url.Path);
		return output;
	}
	auto post(T = string)(URL url, POSTParams data) {
		return post!T(url.Path, data, url.Params);
	}
	auto post(T = string)(URL url, POSTData data) {
		return post!T(url.Path, data, url.Params);
	}
	auto get(T = string)(in string path, URLParameters params = URLParameters.init) @trusted {
		return get!T(URL(url.Protocol, url.Hostname, path, params));
	}
	auto post(T = string)(string path, POSTData inData, URLParameters params = URLParameters.init) @trusted {
		import std.string : representation;
		import std.algorithm : min;
		import etc.c.curl : CurlSeekPos, CurlSeek;
		auto output = Response!T(HTTPClient, URL(url.Protocol, url.Hostname, path, params), peerVerification);
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
	auto post(T = string)(string path, POSTParams data, URLParameters params = URLParameters.init) {
		import std.uri : encode;
		import std.string : join;
		string[] newdata;
		foreach (key, val; data)
			newdata ~= encode(key) ~ "=" ~ encode(val);
		return post!T(path, newdata.join("&"), params);
	}
	auto post(T = string)(string path, in POSTParams data, in URLParameters params = URLParameters.init) {
		return post!T(path, data.dup, params.dup);
	}
	override string toString() {
		return url.toString();
	}
	struct Response(ContentType) {
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
		HTTPStatus statusCode;
		Nullable!string overriddenFilename;
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
			if (!overriddenFilename.isNull)
				return overriddenFilename;
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
		@property HTTPStatus status() {
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
			import std.encoding : transcode;
			if (!fetched)
				fetchContent(false);
			static if (!is(ContentType == string)) {
				string data;
				transcode(cast(ContentType)_content, data);
				return data;
			} else
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
			client.onReceiveStatusLine = (CurlHTTP.StatusLine line) { statusCode = cast(HTTPStatus)line.code; };
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
					if ("content-disposition" in _headers) {
						auto disposition = parseDispositionString(_headers["content-disposition"]);
						if (!disposition.Filename.isNull)
							overriddenFilename = disposition.Filename;
					}
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
					with(HTTPStatus) switch (statusCode) {
						case MovedPermanently, Found, SeeOther, TemporaryRedirect, PermanentRedirect:
							enforce(redirectCount++ < 5, e);
							url = url.absoluteURL(_headers["location"]);
							if ((statusCode == MovedPermanently) || (statusCode == Found) || (statusCode == SeeOther))
								method = CurlHTTP.Method.get;
							break;
						case InternalServerError, BadGateway, ServiceUnavailable, GatewayTimeout:
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
struct ContentDisposition {
	import std.typecons : Nullable;
	Nullable!string Filename;
}
auto parseDispositionString(string str) @safe {
	import std.regex;
	import std.stdio;
	auto output = ContentDisposition();
	auto regex = ctRegex!`attachment;\s*filename\s*=\s*"?([^"]*)"?`;
	auto match = matchFirst(str, regex);
	if (!match.empty)
		output.Filename = match[1];
	return output;
}
unittest {
	assert(parseDispositionString(`attachment; filename=example.txt`).Filename == "example.txt");
	assert(parseDispositionString(`attachment; filename="example.txt"`).Filename == "example.txt");
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
	public HTTPStatus code;
	this(HTTPStatus errorCode, string file = __FILE__, size_t line = __LINE__) @safe pure {
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
	import std.exception, std.file;
	enum testHost = "http://misc.herringway.pw";
	enum testPath = "/.test.php";
	auto httpinstance = httpfactory.spawn(testHost);
	assertNotThrown(httpinstance.get(testPath).md5("7528035a93ee69cedb1dbddb2f0bfcc8").status, "MD5 failure (lowercase)");
	assertNotThrown(httpinstance.get(testPath).md5("7528035A93EE69CEDB1DBDDB2F0BFCC8").status, "MD5 failure (uppercase)");
	assertNotThrown(httpinstance.get(testPath).sha1("f030bbbd32966cde41037b98a8849c46b76e4bc1").status, "SHA1 failure (lowercase)");
	assertNotThrown(httpinstance.get(testPath).sha1("F030BBBD32966CDE41037B98A8849C46B76E4BC1").status, "SHA1 failure (uppercase)");
	assertThrown(httpinstance.get(testPath).md5("7528035A93EE69CEDB1DBDDB2F0BFCC9").status, "Bad MD5 (incorrect hash)");
	assertThrown(httpinstance.get(testPath).md5(""), "Bad MD5 (empty string)");
	assertThrown(httpinstance.get(testPath).md5("BAD").perform(), "Bad MD5 (BAD)");
	assertThrown(httpinstance.get(testPath).sha1("BAD").perform(), "Bad SHA1 (BAD)");
	assertThrown(httpinstance.get(testPath).sha1("F030BBBD32966CDE41037B98A8849C46B76E4BC2").status, "Bad SHA1 (incorrect hash)");

	assertNotThrown(httpinstance.get(testPath).expectedSize(3).status, "Expected size failure (correct size given)");
	assertThrown(httpinstance.get(testPath).expectedSize(4).status, "Expected size failure (intentional bad size)");

	assertNotThrown(httpinstance.post(testPath, "hi").guaranteeData().status);
	assertThrown(httpinstance.post(testPath, "").guaranteeData().status);

	auto tURL = httpfactory.spawn(testHost, ["Referer":testHost]);
	assert(tURL.get(testPath).content == "GET", "GET string failure");
	assert(tURL.get(URL(testPath)).content == "GET", "GET URL failure");
	assert(tURL.get(testPath).status == HTTPStatus.OK, "200 status undetected");
	assert(tURL.get(testPath~"?301").content == "GET");
	assert(tURL.get(testPath~"?301").status == HTTPStatus.MovedPermanently, "301 error undetected");
	assert(tURL.get(testPath~"?302").content == "GET");
	assert(tURL.get(testPath~"?302").status == HTTPStatus.Found, "302 error undetected");
	assert(tURL.get(testPath~"?303").content == "GET");
	assert(tURL.get(testPath~"?303").status == HTTPStatus.SeeOther, "303 error undetected");
	assert(tURL.get(testPath~"?307").content == "GET");
	assert(tURL.get(testPath~"?307").status == HTTPStatus.TemporaryRedirect, "307 error undetected");
	assert(tURL.get(testPath~"?308").content == "GET");
	assertThrown(tURL.get(testPath~"?403").perform());
	assert(tURL.get(testPath~"?403").status == HTTPStatus.Forbidden, "403 error undetected");
	assertThrown(tURL.get(testPath~"?404").perform());
	assert(tURL.get(testPath~"?404").status == HTTPStatus.NotFound, "404 error undetected");
	assertThrown(tURL.get(testPath~"?500").perform());
	assert(tURL.get(testPath~"?500").status == HTTPStatus.InternalServerError, "500 error undetected");
	assert(tURL.post(testPath, "beep").content == "beep", "POST string failed");
	assert(tURL.post(URL(testPath), "beep").content == "beep", "POST URL failed");

	assert(tURL.get(testPath~"?PRINTHEADER").AddHeader("echo", "hello world").content == "hello world", "adding header failed");

	auto a1 = tURL.get("/whack.gif");
	scope(exit) if (exists("whack.gif")) remove("whack.gif");
	scope(exit) if (exists("whack(2).gif")) remove("whack(2).gif");
	scope(exit) if (exists("whack2.gif")) remove("whack2.gif");
	a1.saveTo("whack.gif");
	assert(a1.saveTo("whack.gif", false).path == "whack(2).gif", "failure to rename file to avoid overwriting");
	a1.saveTo("whack2.gif");
	auto resp1 = tURL.post(testPath~"?1", "beep1");
	auto resp2 = tURL.post(testPath~"?2", "beep2");
	assert(resp2.content == "beep2");
	assert(resp2.content == "beep2");
	assert(resp1.content == "beep1");
}