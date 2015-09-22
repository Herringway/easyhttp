module httpinterface.http;
version = Old;

private import httpinterface.fs, httpinterface.url;
private import std.utf : UTFException;
public import stdx.data.json;
public import arsd.dom : Document, Element;

public uint defaultMaxTries = 5;
version(Have_loggins) {
	private import loggins;
} else {
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
version(Old) public alias RequestType = HTTP.Response!string;
version(New) public alias RequestType = HTTPRequest;

public string[] ExtraCurlCertSearchPaths = [];

enum HTTPMethod {
	GET,
	HEAD,
	POST,
	PUT,
	DELETE,
	TRACE,
	OPTIONS,
	CONNECT,
	PATCH
}
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
CURLFactory curlfactory;
static this() {
	httpfactory = HTTPFactory();
	curlfactory = CURLFactory();
}

struct SavedFileInformation {
	string path;
}
class curlClientWrapper {
	import std.net.curl : CurlHTTP = HTTP;
	CurlHTTP* curl;
	alias curl this;
	this() { auto Curl = CurlHTTP(); curl = &Curl; }
}
struct CURLFactory {
	import std.net.curl : CurlHTTP = HTTP;
	import std.typecons : Nullable;
	private curlClientWrapper[string] curlInstances;
	private static Nullable!string certPath;
	static this() @safe {
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
	auto ref spawnInstance(string hostname) {
		if (hostname !in curlInstances)
			curlInstances[hostname] = new curlClientWrapper;
		return &curlInstances[hostname];
	}
}
struct HTTPFactory {
	import std.typecons : Nullable;
	public string CookieJar;
	public uint RetryCount = 5;
	private static Nullable!string certPath;
	static this() @safe {
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
	version(Old) {
		private HTTP[string] activeHTTP;
		HTTP spawn(in URL inURL, URLHeaders reqHeaders = URLHeaders.init) in {
			assert(inURL.Hostname, "Missing hostname in provided URL");
			assert((inURL.Protocol != URL.Proto.Unknown) && (inURL.Protocol != URL.Proto.None) && (inURL.Protocol != URL.Proto.Same), "Bad protocol for provided URL");
		} body {
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
		HTTP.Response!T get(T = string)(URL inURL, URLHeaders headers = URLHeaders.init) {
			return spawn(inURL, headers).get!T(inURL.Path, inURL.Params);
		}
		HTTP.Response!T post(T = string)(URL inURL, string data, URLHeaders headers = URLHeaders.init) {
			return spawn(inURL, headers).post!T(inURL.Path, data, inURL.Params);	
		}
		HTTP.Response!T post(T = string)(URL inURL, string[string] data, URLHeaders headers = URLHeaders.init) {
			return spawn(inURL, headers).post!T(inURL.Path, data, inURL.Params);
		}
	}
	version(New) {
		HTTPRequest get(T = string)(URL inURL, URLHeaders headers = URLHeaders.init) {
			auto output = HTTPRequest(HTTPMethod.GET, inURL, headers);
			return output;
		}
		HTTPRequest post(T = string)(URL inURL, in string data, URLHeaders headers = URLHeaders.init) {
			auto output = HTTPRequest(HTTPMethod.POST, inURL, headers);
			output.POSTData = data;
			return output;
		}
		HTTPRequest post(T = string)(URL inURL, in string[string] data, URLHeaders headers = URLHeaders.init) {
			auto output = HTTPRequest(HTTPMethod.POST, inURL, headers);
			output.POSTData = data;
			return output;
		}	
	}
}

struct HTTPRequest {
	import std.net.curl : CurlHTTP = HTTP;
	import std.typecons : Nullable;
	import core.time : Duration, dur;
	HTTPMethod Method;
	URL url;
	URLHeaders headers;
	URLHeaders outHeaders;
	uint retryCount = 5;
	size_t contentLength;
	bool IgnoreHostCertificate = false;
	bool DisablePeerVerification = false;
	Duration Timeout = dur!"minutes"(5);
	uint MaxTries;
	Nullable!string OAuthBearer;
	Nullable!ulong expectedSize;
	bool guaranteeData = false;
	private Nullable!(ubyte[]) _content;
	private Nullable!(HTTPStatus) _status;
	private Nullable!string overriddenFilename;
	private ubyte[] _POSTData;

	import std.digest.sha : isDigest;

	Hash[string] hashes;
	struct Hash {
		Nullable!string hash;
		Nullable!string original;
		alias hash this;
		this(string inHash) pure @safe {
			original = inHash;
		}
	}

	import std.digest.md : MD5;
	import std.digest.sha : SHA1, SHA256, SHA384, SHA512;
	alias md5 = hash!MD5;
	alias sha1 = hash!SHA1;
	alias sha256 = hash!SHA256;
	alias sha384 = hash!SHA384;
	alias sha512 = hash!SHA512;
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
			if (skipCompleteCheck || !_content.isNull)
				hashes[HashMethod.stringof].hash = getHash!HashMethod;
			return hashes[HashMethod.stringof];
		}
		public Hash hash(bool skipCompleteCheck = false) pure nothrow const {
			Hash output;
			if (HashMethod.stringof in hashes)
				output = hashes[HashMethod.stringof];
			if (skipCompleteCheck || !_content.isNull)
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
	SavedFileInformation saveTo(string dest, bool overwrite = true) {
		return SavedFileInformation();
	}
	void perform(bool ignoreStatus = false) {
		auto client = curlfactory.spawnInstance(url.Hostname);
		ubyte[] contentBuffer;
			import std.digest.sha : toHexString;
			import std.exception : enforce;
			import std.base64, std.conv : to;
			import std.net.curl : CurlException, CurlSeekPos, CurlSeek;
			scope (exit) {
				client.onReceiveHeader = null;
    			client.onReceiveStatusLine = null;
				client.onSend = null;
				client.handle.onSeek = null;
			}
			client.contentLength = contentLength;
			bool stopWriting = false;
			client.onReceive = (ubyte[] data) {
				if (!stopWriting)
			    	contentBuffer ~= data;
			    return data.length;
			};
			if (Method == HTTPMethod.POST) {
				auto remainingData = _POSTData;
			    client.onSend = delegate size_t(void[] buf)
			    {
			    	import std.algorithm : min;
			        size_t minLen = min(buf.length, remainingData.length);
			        if (minLen == 0) return 0;
			        buf[0..minLen] = remainingData[0..minLen];
					LogDebugV("POSTING %s", remainingData[0..minLen]);
			        remainingData = remainingData[minLen..$];
			        return minLen;
			    };
			    client.handle.onSeek = delegate(long offset, CurlSeekPos mode)
			    {
			        switch (mode)
			        {
			            case CurlSeekPos.set:
			                remainingData = _POSTData[cast(size_t)offset..$];
			                return CurlSeek.ok;
			            default:
			                return CurlSeek.cantseek;
			        }
			    };
			}
			client.onReceiveHeader = (in char[] key, in char[] value) {
				if (auto v = key in headers) {
						*v ~= ", ";
						*v ~= value;
				    } else
						headers[key] = value.idup;
			};
			client.connectTimeout(Timeout);
			client.verifyPeer(!DisablePeerVerification);
			client.verifyHost(!IgnoreHostCertificate);
			client.onReceiveStatusLine = (CurlHTTP.StatusLine line) { _status = cast(HTTPStatus)line.code; };
			debug LogTrace("Completed setting curl parameters");
			uint redirectCount = 0;
			Exception lastException;
			client.clearRequestHeaders();
			foreach (key, value; outHeaders)
				client.addRequestHeader(key, value);
			foreach (trial; 0..MaxTries) {
				stopWriting = false;
				client.url = url.toString();
				switch (Method) {
					case HTTPMethod.GET:
						client.method = CurlHTTP.Method.get; break;
					case HTTPMethod.POST:
						client.method = CurlHTTP.Method.post; break;
					case HTTPMethod.HEAD:
						client.method = CurlHTTP.Method.head; break;
					default: throw new Exception("Unsupported method");
				}
				LogDebugV("Fetching %s with method %s from %s (%s)\nOther headers: %s", url, client.method, url.Hostname, url.Protocol, outHeaders);
				try {
					headers = null;
					client.perform();
					stopWriting = true;
					if ("content-disposition" in headers) {
						auto disposition = parseDispositionString(headers["content-disposition"]);
						if (!disposition.Filename.isNull)
							overriddenFilename = disposition.Filename;
					}
					if ("content-md5" in headers)
						enforce(md5(true) == toHexString(Base64.decode(headers["content-md5"])), new HashException("MD5", md5(true), toHexString(Base64.decode(headers["content-md5"]))));
					if ("content-length" in headers)
						enforce(contentBuffer.length == headers["content-length"].to!size_t, new HTTPException("Content length mismatched"));
					if (!expectedSize.isNull)
						enforce(contentBuffer.length == expectedSize, new HTTPException("Size of data mismatched expected size"));
					if (guaranteeData)
						enforce(contentBuffer.length > 0, new HTTPException("No data received"));
					if (!ignoreStatus) 
						enforce(_status < 300, new StatusException(_status));
					if (!md5(true).original.isNull())
						enforce(md5.original == md5.hash, new HashException("MD5", md5.original, md5.hash));
					if (!sha1(true).original.isNull())
						enforce(sha1.original == sha1.hash, new HashException("SHA1", sha1.original, sha1.hash));
					_content = contentBuffer;
					return;
				} catch (CurlException e) {
					lastException = e;
					LogDebugV("%s", e);
				} catch (StatusException e) {
					LogDebugV("HTTP %s error", _status);
					with(HTTPStatus) switch (_status.get()) {
						case MovedPermanently, Found, SeeOther, TemporaryRedirect, PermanentRedirect:
							enforce(redirectCount++ < 5, e);
							url = url.absoluteURL(headers["location"]);
							if ((_status == MovedPermanently) || (_status == Found) || (_status == SeeOther))
								Method = HTTPMethod.GET;
							break;
						case InternalServerError, BadGateway, ServiceUnavailable, GatewayTimeout:
							break;
						default: 
							throw new StatusException(_status);
					}
					lastException = e;
				} catch (HTTPException e) {
					lastException = e;
					LogDebugV("%s", e);
				}
			}
			throw lastException;
	}
	@property {
		string content(ContentType = string)() {
			import std.encoding : transcode;
			if (_content.isNull())
				perform();
			static if (is(ContentType == string)) {
				return cast(string)_content;
			} else if (is(ContentType == ubyte[])) {
				return _content;
			} else if (!is(ContentType == string)) {
				string data;
				transcode(cast(ContentType)_content, data);
				return data;
			}
		}
		string filename() const pure nothrow {
			return "";
		}
		ushort status() {
			if (_status.isNull)
				perform();
			return _status;
		}
		JSONValue json() {
			import std.string : lastIndexOf;
			import stdx.data.json;
			auto a = content[0] == '{' ? lastIndexOf(content, '}') : content.length-1;
			auto fixedContent = content[0..a+1]; //temporary hack
			return parseJSONValue(fixedContent);
		}
		Document dom() {
			return new Document(content);
		}
		void POSTData(in ubyte[] data) {

		}
		void POSTData(in string data) {

		}
		void POSTData(in string[string] data) {

		}
		bool isComplete() const pure nothrow {
			return !_content.isNull;
		}
	}
}

class HTTP {
	import std.net.curl : CurlException, CurlHTTP = HTTP;
	public const(URL) url;

	public uint retryCount = 5;

	private CurlHTTP HTTPClient;
	URLHeaders headers;
	private string _cookiepath;
	private bool peerVerification = false;
	debug static ulong numInstances = 0;
	this(in string inURL, URLHeaders reqHeaders = null) @trusted {
		this(URL(inURL), reqHeaders);
	}
	this(in URL inURL, URLHeaders reqHeaders = null) @trusted {
		import etc.c.curl;
		retryCount = defaultMaxTries;
		url = inURL;

		HTTPClient = CurlHTTP();
		HTTPClient.verifyPeer(false);
		HTTPClient.maxRedirects(uint.max);
		HTTPClient.clearRequestHeaders();
		headers = reqHeaders;
		if ("User-Agent" !in headers)
			headers["User-Agent"] = "curlOO (libcurl/7.34.0)";
		debug numInstances++;
	}
	this(in string hostname, useHTTPS https, URLHeaders reqHeaders) {
		this("http"~(https ? "s" : "")~"://"~hostname, reqHeaders);
	}
	~this() nothrow {
		scope (failure) return;
		HTTPClient.shutdown();
	}
	@property string CookieJar(FileSystemPath path) @trusted in {
		import std.path;
		import std.file;
		assert(dirName(path).isDir, dirName(path)~" is not a directory!");
	} body {
		import std.path : absolutePath, buildNormalizedPath;
		_cookiepath = buildNormalizedPath(path.absolutePath);
		LogDebugV("Setting cookie jar path: %s", _cookiepath);
		HTTPClient.setCookieJar(_cookiepath);
		return _cookiepath;
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
		output.outHeaders = headers;
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
		output.outHeaders = headers;
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
	        try {
				LogDebugV("POSTING %s", cast(string)remainingData[0..minLen]);
	        } catch (UTFException e) {
				LogDebugV("POSTING %s", remainingData[0..minLen]);
			}
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
		URLHeaders _headers;
		URLHeaders outHeaders;
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
		@property bool isComplete() const {
			return fetched;
		}
		void reset() nothrow pure @safe {
			_content = [];
			_headers = null;
			fetched = false;
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
		void guaranteeData(bool val = true) @safe pure nothrow {
			checkNoContent = val;
		}
		@property bool setVerbosity(bool verbose = true) {
			client.verbose = verbose;
			return verbose;
		}
		alias verbose = setVerbosity;
		void AddHeader(string key, string val) {
			outHeaders[key] = val;
		}
		enum OAuthMethod {Header, URL, Form };
		void OAuthBearer(in string token, OAuthMethod method = OAuthMethod.Header) {
			bearerToken = token;
			AddHeader("Authorization", "Bearer "~token);
		}
		void oauth(in string consumerToken, in string consumerSecret, in string token, in string tokenSecret) {
			import std.digest.sha, std.base64, std.conv, std.random, std.datetime, std.string, httpinterface.hmac;
			oAuthParams = OAuthParams(consumerToken, consumerSecret, token, tokenSecret);
			URLParameters params;
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
		}
		void expectedSize(size_t size) {
			sizeExpected = size;
		}
		import std.digest.md : MD5;
		import std.digest.sha : SHA1, SHA256, SHA384, SHA512;
		alias md5 = hash!MD5;
		alias sha1 = hash!SHA1;
		alias sha256 = hash!SHA256;
		alias sha384 = hash!SHA384;
		alias sha512 = hash!SHA512;
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
		void IgnoreHostCertificate(bool val = true) @safe pure nothrow {
			ignoreHostCert = val;
		}
		void DisablePeerVerification(bool val = true) @safe pure nothrow {
			verifyPeer = val;
		}
		void MaxTries(uint max) @safe pure nothrow {
			maxTries = max;
		}
		void Timeout(Duration time) @safe pure nothrow {
			timeout = time;
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
		@property const(URLHeaders) headers() {
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
			foreach (key, value; outHeaders)
				client.addRequestHeader(key, value);
			foreach (trial; 0..maxTries) {
				stopWriting = false;
				client.url = url.toString();
				client.method = method;
				LogDebugV("Fetching %s with method %s from %s (%s)\nOther headers: %s", url, client.method, url.Hostname, url.Protocol, outHeaders);
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
	return httpfactory.get(URL("http://localhost"));
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
	import std.stdio : writeln, writefln;
	enum testHost = "http://misc.herringway.pw";
	enum testPath = "/.test.php";
	enum testURL = URL("http://misc.herringway.pw/.test.php");
	enum testHeaders = ["Referer": testURL.Hostname];
	writeln(httpfactory.get(testURL.withParams(["dump":""])).content);
	assertNotThrown(httpfactory.get(testURL).md5("7528035a93ee69cedb1dbddb2f0bfcc8").status, "MD5 failure (lowercase)");
	assertNotThrown(httpfactory.get(testURL).md5("7528035A93EE69CEDB1DBDDB2F0BFCC8").status, "MD5 failure (uppercase)");
	assertNotThrown(httpfactory.get(testURL).sha1("f030bbbd32966cde41037b98a8849c46b76e4bc1").status, "SHA1 failure (lowercase)");
	assertNotThrown(httpfactory.get(testURL).sha1("F030BBBD32966CDE41037B98A8849C46B76E4BC1").status, "SHA1 failure (uppercase)");
	assertThrown(httpfactory.get(testURL).md5("7528035A93EE69CEDB1DBDDB2F0BFCC9").status, "Bad MD5 (incorrect hash)");
	assertThrown(httpfactory.get(testURL).md5(""), "Bad MD5 (empty string)");
	assertThrown(httpfactory.get(testURL).md5("BAD").perform(), "Bad MD5 (BAD)");
	assertThrown(httpfactory.get(testURL).sha1("BAD").perform(), "Bad SHA1 (BAD)");
	assertThrown(httpfactory.get(testURL).sha1("F030BBBD32966CDE41037B98A8849C46B76E4BC2").status, "Bad SHA1 (incorrect hash)");
 	{
 		auto req = httpfactory.get(testURL);
 		req.expectedSize = 3;
 		assertNotThrown(req.status, "Expected size failure (correct size given)");
 		req = httpfactory.get(testURL);
 		req.expectedSize = 4;
 		assertThrown(req.status, "Expected size failure (intentional bad size)");
 	}
	{
		auto req = httpfactory.post(testURL, "hi");
		req.guaranteeData = true;
		assertNotThrown(req.status);
	}
	{
		auto req = httpfactory.post(testURL, "");
		req.guaranteeData = true;
		assertThrown(req.status);
	}
	assert(httpfactory.get(testURL, testHeaders).content == "GET", "GET URL failure");
	assert(httpfactory.get(testURL, testHeaders).status == HTTPStatus.OK, "200 status undetected");
	assert(httpfactory.get(testURL.withParams(["301":""])).content == "GET");
	assert(httpfactory.get(testURL.withParams(["301":""])).status == HTTPStatus.MovedPermanently, "301 error undetected");
	assert(httpfactory.get(testURL.withParams(["302":""])).content == "GET");
	assert(httpfactory.get(testURL.withParams(["302":""])).status == HTTPStatus.Found, "302 error undetected");
	assert(httpfactory.get(testURL.withParams(["303":""])).content == "GET");
	assert(httpfactory.get(testURL.withParams(["303":""])).status == HTTPStatus.SeeOther, "303 error undetected");
	assert(httpfactory.get(testURL.withParams(["307":""])).content == "GET");
	assert(httpfactory.get(testURL.withParams(["307":""])).status == HTTPStatus.TemporaryRedirect, "307 error undetected");
	assert(httpfactory.get(testURL.withParams(["308":""])).content == "GET");
	assertThrown(httpfactory.get(testURL.withParams(["403":""])).perform());
	assert(httpfactory.get(testURL.withParams(["403":""])).status == HTTPStatus.Forbidden, "403 error undetected");
	assertThrown(httpfactory.get(testURL.withParams(["404":""])).perform());
	assert(httpfactory.get(testURL.withParams(["404":""])).status == HTTPStatus.NotFound, "404 error undetected");
	assertThrown(httpfactory.get(testURL.withParams(["500":""])).perform());
	assert(httpfactory.get(testURL.withParams(["500":""])).status == HTTPStatus.InternalServerError, "500 error undetected");
	assert(httpfactory.post(testURL, "beep", testHeaders).content == "beep", "POST URL failed");

	{
		auto req = httpfactory.get(testURL.withParams(["saveas":"example"]));
		req.perform();
		assert(req.filename == "example", "content-disposition failure");
	}
	{
		auto req = httpfactory.get(testURL.withParams(["PRINTHEADER": ""]));
		req.outHeaders["echo"] = "hello world";
		assert(req.content == "hello world", "adding header failed");
	}
	enum testDownloadURL = URL("http://misc.herringway.pw/whack.gif");
	auto a1 = httpfactory.get(testDownloadURL);
	scope(exit) if (exists("whack.gif")) remove("whack.gif");
	scope(exit) if (exists("whack(2).gif")) remove("whack(2).gif");
	scope(exit) if (exists("whack2.gif")) remove("whack2.gif");
	a1.saveTo("whack.gif");
	assert(a1.saveTo("whack.gif", false).path == "whack(2).gif", "failure to rename file to avoid overwriting");
	a1.saveTo("whack2.gif");
	auto resp1 = httpfactory.post(testURL.withParams(["1": ""]), "beep1");
	auto resp2 = httpfactory.post(testURL.withParams(["2": ""]), "beep2");
	assert(resp2.content == "beep2");
	assert(resp2.content == "beep2");
	assert(resp1.content == "beep1");
	version(Old) debug writefln("Spawned %d instances.", httpfactory.spawn(testURL).numInstances);
}