module easyhttp.http;

private import easyhttp.fs, easyhttp.url;
private import std.utf : UTFException;
public import arsd.dom : Document, Element;
public import siryul : Optional, AsString, SiryulizeAs;

///Default number of times to retry a request
public uint defaultMaxTries = 5;
version(Have_loggins) {
	private import loggins;
} else {
	private void log(T...)(string fmt, T params) {
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
public alias RequestType = HTTP.Request!string;

///Paths to search for certificates
public string[] extraCurlCertSearchPaths = [];

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
///Default HTTP request spawner
HTTPFactory httpfactory;
static this() {
	httpfactory = HTTPFactory();
}
/++
 + Struct for spawning and reusing requests based on hostname.
 +/
struct HTTPFactory {
	import std.typecons : Nullable;
	///Path for the file to store cookies in
	public string cookieJar;
	///Number of times to retry failed requests
	public uint retryCount = 5;
	private static Nullable!string certPath;
	static this() @safe {
		import std.file : exists;
		string[] caCertSearchPaths = extraCurlCertSearchPaths;
		version(Windows) caCertSearchPaths ~= ["./curl-ca-bundle.crt"];
		version(Linux) caCertSearchPaths ~= ["/usr/share/ca-certificates"];
		version(FreeBSD) caCertSearchPaths ~= ["/usr/local/share/certs/ca-root-nss.crt"];
		foreach (path; caCertSearchPaths)
			if (path.exists) {
				certPath = path;
				LogDebugV("Found certs at %s", path);
				break;
			}
	}
	private HTTP[string] activeHTTP;
	private HTTP spawn(in URL inURL, URLHeaders reqHeaders = URLHeaders.init) in {
		assert(inURL.hostname, "Missing hostname in provided URL");
		assert((inURL.protocol != URL.Proto.Unknown) && (inURL.protocol != URL.Proto.None) && (inURL.protocol != URL.Proto.Same), "Bad protocol for provided URL");
	} body {
		LogDebugV("Spawning...%s", inURL);
		if (inURL.hostname !in activeHTTP) {
			activeHTTP[inURL.hostname] = new HTTP(inURL, reqHeaders);
			activeHTTP[inURL.hostname].cookieJar = cookieJar;
			if (!certPath.isNull)
				activeHTTP[inURL.hostname].certificates = certPath;
		}
		return activeHTTP[inURL.hostname];
	}
	/++
	 + Spawns a GET request for the given URL.
	 +/
	HTTP.Request!T get(T = string)(URL inURL, URLHeaders headers = URLHeaders.init) {
		return spawn(inURL, headers).get!T(inURL);
	}
	/++
	 + Spawns a POST request for the given URL.
	 +/
	HTTP.Request!T post(T = string, U)(URL inURL, U data, URLHeaders headers = URLHeaders.init) {
		return spawn(inURL, headers).post!T(inURL, data);
	}
}
/++
 + Creates HTTP Requests for a specified hostname.
 +/
class HTTP {
	import std.net.curl : CurlException, CurlHTTP = HTTP;
	import easyhttp.urlencoding : isURLEncodable, urlEncode;
	///URL that spawned this class
	public const(URL) url;
	///Number of times to retry failed requests
	public uint retryCount = 5;

	private CurlHTTP httpClient;
	private URLHeaders headers;
	private string _cookiepath;
	private bool peerVerification = false;
	///Number of HTTP instances spawned
	debug static ulong numInstances = 0;
	/++
	 + Constructor that takes a URL and optional headers.
	 +/
	this(in URL inURL, URLHeaders reqHeaders = null) {
		import etc.c.curl : LIBCURL_VERSION;
		retryCount = defaultMaxTries;
		url = inURL;

		httpClient = CurlHTTP();
		httpClient.verifyPeer(false);
		httpClient.maxRedirects(uint.max);
		httpClient.clearRequestHeaders();
		headers = reqHeaders;
		if ("User-Agent" !in headers)
			headers["User-Agent"] = "curlOO ("~LIBCURL_VERSION~")";
		debug numInstances++;
	}
	/++
	 + Path for the file to store cookies in.
	 +/
	string cookieJar(FileSystemPath path) @property in {
		import std.path : dirName;
		import std.file : isDir;
		assert(dirName(path).isDir, dirName(path)~" is not a directory!");
	} body {
		import std.path : absolutePath, buildNormalizedPath;
		_cookiepath = buildNormalizedPath(path.absolutePath);
		LogDebugV("Setting cookie jar path: %s", _cookiepath);
		httpClient.setCookieJar(_cookiepath);
		return _cookiepath;
	}
	///ditto
	string cookieJar() @property @safe pure @nogc nothrow {
		return _cookiepath;
	}
	/++
	 + Path to the system's certificate store.
	 +/
	string certificates(FileSystemPath path) {
		import std.exception : enforce;
		import std.file : exists;
		enforce(path.exists(), "Certificate path not found");
		httpClient.caInfo = path;
		httpClient.verifyPeer = true;
		peerVerification = true;
		return path;
	}
	/++
	+ Prepares an HTTP GET request.
	+/
	auto get(T = string)(URL inURL) {
		auto output = Request!(T)(&httpClient, url.absoluteURL(inURL), peerVerification);
		output.outHeaders = headers;
		output.method = CurlHTTP.Method.get;
		output.onReceive = null;
		output.maxTries = retryCount;
		return output;
	}
	/++
	 + Prepares an HTTP POST request.
	 +
	 + Params:
	 +  url = URL being POSTed to
	 +  inData = Data being POSTed
	 +/
	auto post(T = string, U)(URL url, U inData) if (isURLEncodable!U) {
		return post!T(url, urlEncode(inData));
	}
	///ditto
	auto post(T = string)(URL url, POSTData inData) {
		import std.string : representation;
		import std.algorithm : min;
		import etc.c.curl : CurlSeekPos, CurlSeek;
		auto output = Request!T(&httpClient, url, peerVerification);
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
		return output;
	}
	override string toString() @safe const {
		return url.toString();
	}
	/++
	 + An HTTP Request.
	 +/
	struct Request(ContentType) {
		private struct Hash {
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
		import std.json: JSONValue;
		private struct OAuthParams {
			string consumerToken;
			string consumerSecret;
			string token;
			string tokenSecret;
		}
		private string bearerToken;
		private const(ubyte)[] _content;
		private URLHeaders _headers;
		private URLHeaders outHeaders;
		private Nullable!size_t sizeExpected;
		private CurlHTTP* client;
		private bool fetched = false;
		private bool checkNoContent = false;
		///Maximum number of tries to retry the request
		uint maxTries;
		///Maximum time to wait for the request to complete
		Duration timeout = dur!"minutes"(5);
		///The URL being requested
		URL url;
		package size_t delegate(ubyte[]) onReceive;
		package CurlSeek delegate(long offset, CurlSeekPos mode) onSeek;
		package size_t delegate(void[] buf) onSend;
		///Length of the data in the body
		uint contentLength;
		package CurlHTTP.Method method;
		private OAuthParams oAuthParams;
		///Whether or not to ignore errors in the server's SSL certificate
		bool ignoreHostCert = false;
		///Whether or not to verify the name specified in the server certificate
		bool verifyPeer = true;
		///The HTTP status code last seen
		HTTPStatus statusCode;
		///Change filename for saved files
		Nullable!string overriddenFilename;
		invariant() {
			import std.algorithm : among;
			assert(!url.protocol.among(Proto.Unknown, Proto.None, Proto.Same), "No protocol specified in URL \""~url.toString()~"\"");
			assert(_isValid, "Dead curl instance!");
		}
		private this(CurlHTTP* inClient, URL initial, bool peerVerification) @safe nothrow {
			verifyPeer = peerVerification;
			client = inClient;
			url = initial;
		}
		/++
		 + Whether or not the request has been completed successfully.
		 +/
		bool isComplete() @property const @safe pure nothrow @nogc {
			return fetched;
		}
		/++
		 + Reset the state of this request.
		 +/
		void reset() nothrow pure @safe {
			_content = [];
			_headers = null;
			fetched = false;
		}
		/++
		 + The default filename for the file being requested.
		 +/
		string filename() @property nothrow const pure {
			if (!overriddenFilename.isNull)
				return overriddenFilename;
			return url.fileName;
		}
		private bool _isValid() @property nothrow const {
			try {
				return !(cast()*client).isStopped();
			} catch (Exception) {
				return false;
			}
		}
		/++
		 + Whether this request is still valid or not.
		 +/
		bool isValid() @property nothrow const {
			return _isValid;
		}
		/++
		 + Information about a file saved with the saveTo function.
		 +/
		struct SavedFileInformation {
			///Path that was used for actually saving the file.
			string path;
		}
		/++
		 + Saves the body of this request to a local path.
		 +
		 + Will not overwrite existing files unless overwrite is set.
		 +
		 + Params:
		 +  dest = default destination for the file to be saved
		 +  overwrite = whether or not to overwrite existing files
		 +/
		SavedFileInformation saveTo(string dest, bool overwrite = true) {
			import std.file : exists, mkdirRecurse;
			import std.path : dirName;
			import std.stdio : File;
			auto output = SavedFileInformation();
			if (!overwrite)
				while (exists(dest))
					dest = duplicateName(dest);
			output.path = dest;
			if (!exists(dest.dirName()))
				mkdirRecurse(dest.dirName());
			dest = dest.fixPath();
			auto outFile = File(dest, "wb");
			scope(exit) 
				if (outFile.isOpen) {
					outFile.flush();
					outFile.close();
				}
			onReceive = (ubyte[] data) { _content ~= data; outFile.rawWrite(data); return data.length; };
			outFile.seek(0);
			if (!fetched)
				fetchContent();
			else
				outFile.rawWrite(_content);
			return output;
		}
		/++
		 + The HTTP status code for a completed request.
		 +
		 + Completes the request if not already done.
		 +/
		HTTPStatus status() @property {
			if (!fetched)
				fetchContent(true);
			return statusCode;
		}
		/++
		 + Whether or not this request should fail upon receiving an empty body.
		 +/
		ref bool guaranteedData() @property @safe pure nothrow @nogc {
			return checkNoContent;
		}
		/++
		 + Print debugging information.
		 +/
		void verbose(bool val) @property {
			client.verbose = val;
		}
		/++
		 + Adds an outgoing header to the request.
		 +
		 + No effect on completed requests.
		 +/
		void addHeader(string key, string val) @safe pure nothrow {
			outHeaders[key] = val;
		}
		enum OAuthMethod {Header, URL, Form }
		/++
		 + Adds an OAuth bearer token to the request.
		 +
		 + Valid methods are OAuthMethod.Header.
		 +/
		void oAuthBearer(in string token, OAuthMethod method = OAuthMethod.Header) {
			bearerToken = token;
			if (method == OAuthMethod.Header)
				addHeader("Authorization", "Bearer "~token);
		}
		/+void oauth(in string consumerToken, in string consumerSecret, in string token, in string tokenSecret) {
			import std.digest.sha, std.base64, std.conv, std.random, std.datetime, std.string, httpinterface.hmac;
			oAuthParams = OAuthParams(consumerToken, consumerSecret, token, tokenSecret);
			URLParameters params;
			auto copy_url = URL(url.protocol, url.hostname, url.Path, url.params);
			params["oauth_consumer_key"] = copy_url.params["oauth_consumer_key"] = [oAuthParams.consumerToken];
			params["oauth_token"] = copy_url.params["oauth_token"] = [oAuthParams.token];
			params["oauth_nonce"] = copy_url.params["oauth_nonce"] = [to!string(uniform(uint.min, uint.max)) ~ to!string(Clock.currTime().stdTime)];
			//params["oauth_nonce"] = copy_url.params["oauth_nonce"] = "1771511773635420822306363698";
			params["oauth_signature_method"] = copy_url.params["oauth_signature_method"] = ["HMAC-SHA1"];
			params["oauth_timestamp"] = copy_url.params["oauth_timestamp"] = [to!string(Clock.currTime().toUTC().toUnixTime())];
			//params["oauth_timestamp"] = copy_url.params["oauth_timestamp"] = "1406485430";
			params["oauth_version"] = copy_url.params["oauth_version"] = ["1.0"];
			string signature = [std.uri.encodeComponent(oAuthParams.consumerSecret), std.uri.encodeComponent(oAuthParams.tokenSecret)].join("&");
			//writeln(signature, "\n", [std.uri.encodeComponent(text(method).toUpper()), std.uri.encodeComponent(copy_url.str), std.uri.encodeComponent(copy_url.paramString)].join("&"));
			params["oauth_signature"] = [Base64.encode(HMAC!SHA1(signature, std.uri.encodeComponent(text(method).toUpper())~"&"~std.uri.encodeComponent(copy_url.toString(false))~"&"~std.uri.encodeComponent(copy_url.paramString)))];
			params["realm"] = [""];

			string[] authString;
			foreach (k,dv; params)
				foreach (v; dv)
					authString ~= format(`%s="%s"`, k, std.uri.encodeComponent(v));
			LogDebugV("Oauth: %(%s,\n%)", authString);
			LogDebugV("Adding header: Authorization: %s", "OAuth " ~ authString.join(", "));
			AddHeader("Authorization", "OAuth " ~ authString.join(", "));
		}+/
		/++
		 + The expected size of the body if available.
		 +
		 + Null if no size is known.
		 +/
		ref Nullable!size_t expectedSize() @safe nothrow pure @nogc @property {
			return sizeExpected;
		}
		import std.digest.md : MD5;
		import std.digest.sha : SHA1, SHA256, SHA384, SHA512;
		private Hash[string] hashes;
		alias md5 = hash!MD5;
		alias sha1 = hash!SHA1;
		alias sha256 = hash!SHA256;
		alias sha384 = hash!SHA384;
		alias sha512 = hash!SHA512;
		private template hash(HashMethod) {
			/++
			 + Sets an expected hash for the request.
			 +/
			void hash(string hash) pure in {
				import std.string : removechars;
				assert(hash.removechars("[0-9a-fA-F]") == [], "Non-hexadecimal characters found in hash");
			} body {
				import std.digest.digest : digestLength;
				import std.string : toUpper, format;
				import std.exception : enforce;
				enforce(hash.length == 2*digestLength!HashMethod, format("%s hash strings must be %s characters in length", HashMethod.stringof, 2*digestLength!HashMethod));
				hashes[HashMethod.stringof] = Hash(hash.toUpper());
			}
			/++
			 + Gets the hash of the request body.
			 +
			 + Empty if request is incomplete.
			 +/
			public Hash hash(bool skipCompleteCheck = false) pure nothrow {
				if (HashMethod.stringof !in hashes)
					hashes[HashMethod.stringof] = Hash();
				if (skipCompleteCheck || fetched)
					hashes[HashMethod.stringof].hash = getHash!HashMethod;
				return hashes[HashMethod.stringof];
			}
			///ditto
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
		/++
		 + Whether or not to ignore errors in the server's SSL certificate.
		 +/
		ref bool ignoreHostCertificate() @property @nogc @safe pure nothrow {
			return ignoreHostCert;
		}
		/++
		 + Whether or not to validate the peer named in the server's SSL cert.
		 +/
		ref bool peerVerification() @property @nogc @safe pure nothrow {
			return verifyPeer;
		}
		/++
		 + Returns body of response as a string.
		 +/
		string content() @property {
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
		/++
		 + Returns body of response as parsed JSON.
		 +
		 + If a type T is specified, an attempt at automatically deserializing
		 + the JSON as the specified type is made.
		 +
		 + Params:
		 +  T = optional type to attempt deserialization to
		 +/
		T json(T = JSONValue)() @property {
			import std.string : lastIndexOf;
			auto a = content[0] == '{' ? lastIndexOf(content, '}') : content.length-1;
			auto fixedContent = content[0..a+1]; //temporary hack
			static if (is(T==JSONValue)) {
				import std.json: parseJSON;
				return parseJSON(fixedContent);
			} else {
				import siryul : fromString, JSON;
				return fixedContent.fromString!(T,JSON);
			}
		}
		/++
		 + Returns body of response as a parsed HTML document.
		 +
		 + See arsd.dom for details and usage.
		 +/
		Document dom() @property {
			return new Document(content);
		}
		/++
		 + Performs the request.
		 +/
		void perform(bool ignoreStatus = false) {
			if (!fetched)
				fetchContent(ignoreStatus);
		}
		/++
		 + Returns headers of response.
		 +
		 + Performs the request if not already done.
		 +/
		const(URLHeaders) headers() @property {
			if (!fetched)
				fetchContent(true);
			return _headers;
		}
		private void fetchContent(bool ignoreStatus = false) in {
			assert(maxTries > 0, "Max tries set to zero?");
		} body {
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
			uint redirectCount = 0;
			Exception lastException;
			client.clearRequestHeaders();
			foreach (key, value; outHeaders)
				client.addRequestHeader(key, value);
			foreach (trial; 0..maxTries) {
				stopWriting = false;
				client.url = url.toString();
				client.method = method;
				LogDebugV("Fetching %s with method %s from %s (%s)\nOther headers: %s", url, client.method, url.hostname, url.protocol, outHeaders);
				try {
					_content = [];
					_headers = null;
					client.perform();
					stopWriting = true;
					if ("content-disposition" in _headers) {
						immutable disposition = parseDispositionString(_headers["content-disposition"]);
						if (!disposition.filename.isNull)
							overriddenFilename = disposition.filename;
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
							LogDebugV("Changing URL to %s and retrying", _headers["location"]);
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
/++
 + A parsed content-disposition string
 +/
struct ContentDisposition {
	import std.typecons : Nullable;
	///Filename extracted from the header, if available
	Nullable!string filename;
}
/++
 + Parses a content-disposition header's contents.
 +
 + Currently only extracts a filename.
 +
 + Params:
 +  str = Header string to parse
 +/
auto parseDispositionString(string str) @safe {
	import std.regex : ctRegex, matchFirst;
	auto output = ContentDisposition();
	auto regex = ctRegex!`attachment;\s*filename\s*=\s*"?([^"]*)"?`;
	auto match = matchFirst(str, regex);
	if (!match.empty)
		output.filename = match[1];
	return output;
}
unittest {
	assert(parseDispositionString(`attachment; filename=example.txt`).filename == "example.txt");
	assert(parseDispositionString(`attachment; filename="example.txt"`).filename == "example.txt");
}
/++
 + A useless HTTP request for testing
 +/
auto nullResponse() @property {
	return httpfactory.get(URL("http://localhost"));
}
/++
 + Exception thrown when an unexpected status is encountered.
 +/
class StatusException : HTTPException {
	///The HTTP status code that was seen
	public HTTPStatus code;
	/++
	 + Constructor that takes an HTTP status code.
	 +
	 + Params:
	 +  errorCode = The HTTP status code encountered
	 +  file = The file where the error occurred
     +  line = The line where the error occurred
	 +/
	this(HTTPStatus errorCode, string file = __FILE__, size_t line = __LINE__) @safe pure {
		import std.string : format;
		code = errorCode;
		super(format("Error %d fetching URL", errorCode), file, line);
	}
}
/++
 + Exception thrown on hash mismatches.
 +/
class HashException : HTTPException {
	/++
	 + Constructor that takes a hash algorithm name and two compared hashes.
	 +
	 + Params:
	 +  hashType = The hash algorithm name that detected a mismatch
	 +  badHash = The mismatched hash
	 +  goodHash = The hash being compared to
	 +  file = The file where the error occurred
     +  line = The line where the error occurred
	 +/
	this(string hashType, string badHash, string goodHash, string file = __FILE__, size_t line = __LINE__) @safe pure in {
		assert(goodHash != badHash, "Good hash and mismatched hash match!");
	} body {
		import std.string : format;
		super(format("Hash mismatch (%s): %s != %s", hashType, badHash, goodHash), file, line);
	}
}
/++
 + Exception encompassing all HTTP problems.
 +/
class HTTPException : Exception {
	/++
	 + Constructor that takes an error message.
	 +
	 + Params:
	 +  msg = A message describing the error
	 +  file = The file where the error occurred
     +  line = The line where the error occurred
	 +/
	this(string msg, string file = __FILE__, size_t line = __LINE__) @safe nothrow pure {
		super(msg, file, line);
	}
}
unittest {
	import std.exception : assertNotThrown, assertThrown;
	import std.file : remove, exists;
	import std.stdio : writeln, writefln;
	enum testURL = URL("http://misc.herringway.pw/.test.php");
	enum testHeaders = ["Referer": testURL.hostname];
	{
		auto req = httpfactory.get(testURL);
		req.md5 = "7528035a93ee69cedb1dbddb2f0bfcc8";
		assertNotThrown(req.status, "MD5 failure (lowercase)");
	}
	{
		auto req = httpfactory.get(testURL);
		req.md5 = "7528035A93EE69CEDB1DBDDB2F0BFCC8";
		assertNotThrown(req.status, "MD5 failure (uppercase)");
	}
	{
		auto req = httpfactory.get(testURL);
		req.sha1 = "f030bbbd32966cde41037b98a8849c46b76e4bc1";
		assertNotThrown(req.status, "SHA1 failure (lowercase)");
	}
	{
		auto req = httpfactory.get(testURL);
		req.sha1 = "F030BBBD32966CDE41037B98A8849C46B76E4BC1";
		assertNotThrown(req.status, "SHA1 failure (uppercase)");
	}
	{
		auto req = httpfactory.get(testURL);
		req.md5 = "7528035A93EE69CEDB1DBDDB2F0BFCC9";
		assertThrown(req.status, "Bad MD5 (incorrect hash)");
	}
	{
		auto req = httpfactory.get(testURL);
		assertThrown(req.md5 = "", "Bad MD5 (empty string)");
	}
	{
		auto req = httpfactory.get(testURL);
		assertThrown(req.md5 = "BAD", "Bad MD5 (BAD)");
	}
	{
		auto req = httpfactory.get(testURL);
		assertThrown(req.sha1 = "BAD", "Bad SHA1 (BAD)");
	}
	{
		auto req = httpfactory.get(testURL);
		req.sha1 = "F030BBBD32966CDE41037B98A8849C46B76E4BC2";
		assertThrown(req.status, "Bad SHA1 (incorrect hash)");
	}
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
		req.guaranteedData = true;
		assertNotThrown(req.status);
	}
	{
		auto req = httpfactory.post(testURL, "");
		req.guaranteedData = true;
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
	debug writefln("Spawned %d instances.", httpfactory.spawn(testURL).numInstances);
}