module easyhttp.http;

import core.time;

import std.algorithm;
import std.array;
import std.base64;
import std.conv;
import std.datetime;
import std.digest.digest;
import std.digest.hmac;
import std.digest.md;
import std.digest.sha;
import std.encoding;
import std.exception;
import std.file;
import std.json;
import std.path;
import std.random;
import std.range;
import std.regex;
import std.stdio;
import std.string;
import std.typecons;
import std.uri;
import std.utf;

import easyhttp.fs;
import easyhttp.url;
import easyhttp.urlencoding;

enum packageName = "easyhttp";
enum packageVersion = "v0.0.0";

alias useHTTPS = bool;
alias POSTData = string;
alias POSTParams = string[string];

///Paths to search for certificates
public string[] extraCurlCertSearchPaths = [];

enum HTTPMethod {
	get,
	head,
	post,
	put,
	delete_,
	trace,
	options,
	connect,
	patch
}
enum POSTStyle {
	xWWWFormUrlencoded,
	formData,
	raw
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
enum OAuthMethod { header, queryString, form }
struct Cookie {
	string domain;
	string path;
	string key;
	string value;
}
immutable Nullable!(string, "") systemCertPath;
shared static this() {
	version(Windows) immutable caCertSearchPaths = ["./curl-ca-bundle.crt"];
	version(Linux) immutable caCertSearchPaths = ["/usr/share/ca-certificates"];
	version(FreeBSD) immutable caCertSearchPaths = ["/usr/local/share/certs/ca-root-nss.crt"];
	foreach (path; caCertSearchPaths)
		if (path.exists) {
			systemCertPath = Nullable!(string, "")(path);
			break;
		}
}

auto get(URL inURL, URLHeaders headers = URLHeaders.init) @safe pure {
	auto result = Request(inURL);
	result.method = HTTPMethod.get;
	result.outHeaders = headers;
	return result;
}
@safe pure nothrow unittest {
	auto get1 = get(URL(URL.Proto.HTTPS, "localhost"));
	auto get2 = get(URL(URL.Proto.HTTPS, "localhost"), ["":""]);
}
auto post(T = string, U)(URL inURL, U data, URLHeaders headers = URLHeaders.init) if (isURLEncodable!U || is(U == POSTData)) {
	auto result = Request(inURL);
	result.method = HTTPMethod.post;
	static if (is(U == ubyte[])) {
		result.rawPOSTData = data;
		result.postDataType = POSTDataType.raw;
	} else static if (is(U == string)) {
		result.rawPOSTData = data.representation.dup;
		result.postDataType = POSTDataType.raw;
	} else static if (isURLEncodable!U) {
		result.formPOSTData = urlEncode(data);
		result.postDataType = POSTDataType.form;
	}
	result.outHeaders = headers;
	return result;
}
@safe pure unittest {
	auto post1 = post(URL(URL.Proto.HTTPS, "localhost"), "");
	auto post2 = post(URL(URL.Proto.HTTPS, "localhost"), "", ["":""]);
	auto post3 = post(URL(URL.Proto.HTTPS, "localhost"), ["":""], ["":""]);
	auto post4 = post(URL(URL.Proto.HTTPS, "localhost"), ["":[""]], ["":""]);
}
enum POSTDataType {
	none,
	raw,
	form
}
/++
 + An HTTP Request.
 +/
struct Request {
	import requests.utils : QueryParam;
	private struct Hash {
		Nullable!string hash;
		Nullable!string original;
		this(string inHash) pure @safe {
			original = inHash;
		}
	}
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
	private Cookie[] outCookies;
	private Nullable!size_t sizeExpected;
	private bool fetched = false;
	private bool checkNoContent = false;
	///Maximum time to wait for the request to complete
	Duration timeout = dur!"minutes"(5);
	///The URL being requested
	Nullable!URL url;
	package HTTPMethod method;
	private OAuthParams oAuthParams;
	///The HTTP status code last seen
	HTTPStatus statusCode;
	///Change filename for saved files
	Nullable!string overriddenFilename;
	///Certificate root store
	Nullable!string certPath;
	///Whether or not to ignore errors in the server's SSL certificate
	bool ignoreHostCert = false;
	///Whether or not to verify the certificate for HTTPS connections
	bool peerVerification = true;
	///Whether to output verbose debugging information to stdout
	bool verbose;
	string contentType = "application/octet-stream";
	Cookie[] cookies;
	private POSTDataType postDataType;
	private QueryParam[] formPOSTData;
	private ubyte[] rawPOSTData;

	private Nullable!string outFile;
	invariant() {
		if (!url.isNull) {
			assert(!url.get.protocol.among(URL.Proto.Unknown, URL.Proto.None, URL.Proto.Same), "No protocol specified in URL \""~url.get.text~"\"");
		}
	}
	private this(URL initial) @safe pure nothrow {
		debug(verbosehttp) verbose = true;
		if ("User-Agent" !in outHeaders) {
			outHeaders["User-Agent"] = packageName ~ " " ~ packageVersion;
		}
		url = initial;
	}
	/++
	 + Whether or not the request has been completed successfully.
	 +/
	bool isComplete() const @safe pure nothrow @nogc {
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
	string filename() nothrow const pure @safe {
		if (!overriddenFilename.isNull) {
			return overriddenFilename.get;
		}
		return url.get.fileName;
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
	 +  clearAfterComplete = whether or not to clear the buffer after success
	 +/
	SavedFileInformation saveTo(string dest, bool overwrite = true, bool clearAfterComplete = false) {
		scope(success) {
			if (clearAfterComplete) {
				reset();
			}
		}
		auto output = SavedFileInformation();
		if (!overwrite)
			while (exists(dest))
				dest = duplicateName(dest);
		output.path = dest;
		if (!exists(dest.dirName()))
			mkdirRecurse(dest.dirName());
		dest = dest.fixPath();
		if (!fetched) {
			outFile = dest;
			fetchContent();
		}
		else {
			auto writeFile = File(dest, "wb");

			scope(exit) {
				if (writeFile.isOpen) {
					writeFile.flush();
					writeFile.close();
				}
			}
			writeFile.rawWrite(_content);
		}
		return output;
	}
	/++
	 + The HTTP status code for a completed request.
	 +
	 + Completes the request if not already done.
	 +/
	HTTPStatus status() {
		if (!fetched)
			fetchContent(true);
		return statusCode;
	}
	/++
	 + Whether or not this request should fail upon receiving an empty body.
	 +/
	ref bool guaranteedData() @safe pure nothrow @nogc {
		return checkNoContent;
	}
	/++
	 + Adds an outgoing header to the request.
	 +
	 + No effect on completed requests.
	 +/
	void addHeader(string key, string val) @safe pure nothrow {
		outHeaders[key] = val;
	}
	/++
	 + Adds an OAuth bearer token to the request.
	 +
	 + Valid methods are OAuthMethod.header.
	 +/
	void oAuthBearer(in string token, OAuthMethod method = OAuthMethod.header) @safe pure {
		bearerToken = token;
		if (method == OAuthMethod.header) {
			addHeader("Authorization", "Bearer "~token);
		}
	}
	void oauth(Hash = SHA1)(OAuthMethod oauthMethod, in string consumerToken, in string consumerSecret, in string token, in string tokenSecret) @safe {
		static if (is(Hash == SHA1))
			enum hashType = "SHA1";
		else static if (is(Hash == MD5))
			enum hashType = "MD5";
		else static assert(0, "Unknown hash");
		oAuthParams = OAuthParams(consumerToken, consumerSecret, token, tokenSecret);
		URLParameters params;
		auto copy_url = URL(url.get.protocol, url.get.hostname, url.get.path, url.get.params);
		params["oauth_consumer_key"] = copy_url.params["oauth_consumer_key"] = [oAuthParams.consumerToken];
		params["oauth_token"] = copy_url.params["oauth_token"] = [oAuthParams.token];
		params["oauth_nonce"] = copy_url.params["oauth_nonce"] = [uniform(uint.min, uint.max).text ~ Clock.currTime().stdTime.text];
		params["oauth_signature_method"] = copy_url.params["oauth_signature_method"] = ["HMAC-"~hashType];
		params["oauth_timestamp"] = copy_url.params["oauth_timestamp"] = [Clock.currTime().toUTC().toUnixTime().text];
		params["oauth_version"] = copy_url.params["oauth_version"] = ["1.0"];
		string signature = [encodeComponentSafe(oAuthParams.consumerSecret), encodeComponentSafe(oAuthParams.tokenSecret)].join("&");
		auto signer = HMAC!Hash(signature.representation);
		auto baseString = only(encodeComponentSafe(method.text.toUpper()), encodeComponentSafe(copy_url.toString(false)), encodeComponentSafe(copy_url.paramString)).map!representation.joiner("&".representation);

		put(signer, baseString);

		params["oauth_signature"] = [Base64.encode(signer.finish())];
		params["realm"] = [""];
		if (oauthMethod == OAuthMethod.header) {
			string[] authString;
			foreach (k, dv; params) {
				foreach (v; dv) {
					authString ~= format(`%s="%s"`, k, encodeComponentSafe(v).replace("+", "%2B"));
				}
			}
			addHeader("Authorization", "OAuth " ~ authString.join(", "));
		}
		if (oauthMethod == OAuthMethod.queryString) {
			enforce(!url.isNull, "can't add oauth params to nonexistant URL");
			url.get.params["oauth_version"] = ["1.0"];
			url.get.params["oauth_signature"] = params["oauth_signature"];
			url.get.params["oauth_signature_method"] = params["oauth_signature_method"];
			url.get.params["oauth_nonce"] = params["oauth_nonce"];
			url.get.params["oauth_timestamp"] = params["oauth_timestamp"];
			url.get.params["oauth_consumer_key"] = params["oauth_consumer_key"];
			url.get.params["oauth_token"] = params["oauth_token"];
		}
	}

	void authorizationBasic(string user, string pass) {
		addHeader("Authorization", "Basic "~Base64.encode((user~":"~pass).representation).idup);
	}
	/++
	 + The expected size of the body if available.
	 +
	 + Null if no size is known.
	 +/
	ref Nullable!size_t expectedSize() @safe nothrow pure @nogc {
		return sizeExpected;
	}
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
		void hash(string hash) @safe pure in {
			assert(hash[].filter!(x => !(x >= '0' && x <= '9') && !(x >= 'a' && x <= 'f') && !(x >= 'A' && x <= 'F')).empty, "Non-hexadecimal characters found in hash");
		} body {
			enforce(hash.length == 2*digestLength!HashMethod, format("%s hash strings must be %s characters in length", HashMethod.stringof, 2*digestLength!HashMethod));
			hashes[HashMethod.stringof] = Hash(hash.toUpper());
		}
		void hash(immutable(char)[2*digestLength!HashMethod] str) @safe pure nothrow in {
			assert(str[].filter!(x => !(x >= '0' && x <= '9') && !(x >= 'a' && x <= 'f') && !(x >= 'A' && x <= 'F')).empty, "Non-hexadecimal characters found in hash");
		} body {
			hashes[HashMethod.stringof] = assumeWontThrow(Hash(str[].toUpper().dup));
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
		auto hash = makeDigest!HashMethod;
		hash.put(_content);
		return hash.finish().toHexString!(Order.increasing, LetterCase.upper);
	}
	/++
	 + Whether or not to ignore errors in the server's SSL certificate.
	 +/
	ref bool ignoreHostCertificate() @nogc @safe pure nothrow {
		return ignoreHostCert;
	}
	/++
	 + Returns body of response as a string.
	 +/
	T content(T = string)() {
		if (!fetched)
			fetchContent(false);
		return contentInternal!T;
	}
	/++
	 +
	 +/
	 T content(T = string)() const {
		enforce(fetched);
		return contentInternal!T;
	 }
	 private T contentInternal(T = string)() const {
		static if (is(T == string)) {
			return _content.assumeUTF;
		} else
			return _content.to!T;
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
	const(URLHeaders) headers() {
		if (!fetched)
			fetchContent(true);
		return _headers;
	}
	//fetch content using requests library
	private void fetchContent(bool ignoreStatus = false) in {
		assert(!url.isNull, "URL not set");
	} body {
		import requests;
		auto req = requests.Request();
		req.verbosity = verbose ? 3 : 0;
		if (!systemCertPath.isNull) {
			req.sslSetCaCert(systemCertPath);
		}
		if (!certPath.isNull) {
			enforce(certPath.get.exists, "Certificate path not found");
			req.sslSetCaCert(certPath.get);
		}
		req.addHeaders(outHeaders);
		req.sslSetVerifyPeer(peerVerification);
		if (!outFile.isNull) {
			req.useStreaming = true;
		}
		RefCounted!Cookies reqCookies;
		foreach (cookie; cookies) {
			alias ReqCookie = requests.Cookie;
			reqCookies ~= ReqCookie(cookie.path, cookie.domain, cookie.key, cookie.value);
		}
		req.cookie = reqCookies;
		Response response;
		final switch(method) {
			case HTTPMethod.post:
				final switch (postDataType) {
					case POSTDataType.none:
						response = req.post(url.text, string[string].init);
						break;
					case POSTDataType.form:
						response = req.post(url.text, formPOSTData);
						break;
					case POSTDataType.raw:
						response = req.post(url.text, rawPOSTData, contentType);
						break;
				}
				break;
			case HTTPMethod.get:
				response = req.get(url.text);
				break;
			case HTTPMethod.head, HTTPMethod.put, HTTPMethod.delete_, HTTPMethod.trace, HTTPMethod.options, HTTPMethod.connect, HTTPMethod.patch:
				assert(0);
		}
		assert(response !is null);
		if (!outFile.isNull) {
			response.receiveAsRange().copy(File(outFile.get, "wb").lockingBinaryWriter);
		} else {
			_content = response.responseBody.data;
		}
		statusCode = cast(HTTPStatus)response.code;
		_headers = response.responseHeaders;
		foreach (cookie; req.cookie) {
			outCookies ~= Cookie(cookie.domain, cookie.path, cookie.attr, cookie.value);
		}
		if ("content-disposition" in _headers) {
			immutable disposition = parseDispositionString(_headers["content-disposition"]);
			if (!disposition.filename.isNull)
				overriddenFilename = disposition.filename;
		}
		if ("content-md5" in _headers) {
			enforce(md5(true).hash.get == toHexString(Base64.decode(_headers["content-md5"])), new HashException("MD5", md5(true).hash.get, toHexString(Base64.decode(_headers["content-md5"]))));
		}
		if ("content-length" in _headers) {
			if (!outFile.isNull) {
				enforce(File(outFile.get, "r").size == _headers["content-length"].to!ulong, new HTTPException("Content length mismatched"));
			} else {
				enforce(response.contentLength == _headers["content-length"].to!size_t, new HTTPException("Content length mismatched"));
			}
		}
		if (!md5(true).original.isNull()) {
			enforce(md5.original == md5.hash, new HashException("MD5", md5.original.get, md5.hash.get));
		}
		if (!sha1(true).original.isNull()) {
			enforce(sha1.original == sha1.hash, new HashException("SHA1", sha1.original.get, sha1.hash.get));
		}
		if (!sizeExpected.isNull) {
			enforce(_content.length == sizeExpected.get, new HTTPException("Size of data mismatched expected size"));
		}
		if (checkNoContent) {
			enforce(_content.length > 0, new HTTPException("No data received"));
		}
		if (!ignoreStatus) {
			enforce(statusCode < 300, new StatusException(statusCode, url.get));
		}
		fetched = true;
	}
}
/++
 + A parsed content-disposition string
 +/
struct ContentDisposition {
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
	auto output = ContentDisposition();
	auto regex = ctRegex!`attachment;\s*filename\s*=\s*"?([^"]*)"?`;
	auto match = matchFirst(str, regex);
	if (!match.empty)
		output.filename = match[1];
	return output;
}
@safe unittest {
	assert(parseDispositionString(`attachment; filename=example.txt`).filename == "example.txt");
	assert(parseDispositionString(`attachment; filename="example.txt"`).filename == "example.txt");
}
/++
 + A useless HTTP request for testing
 +/
auto nullResponse() {
	return get(URL(URL.Proto.HTTP, "localhost", "/"));
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
	this(HTTPStatus errorCode, URL url, string file = __FILE__, size_t line = __LINE__) {
		code = errorCode;
		super(format("Error %d (%s) fetching URL %s", errorCode, errorCode, url), file, line);
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
//Test to ensure initial construction is safe, pure, and nothrow
@safe pure nothrow unittest {
	get(URL(URL.Proto.HTTP, "localhost", "/"));
}
//will be @safe once requests supports it
@system unittest {
	import std.exception : assertNotThrown, assertThrown;
	import std.file : remove, exists;
	import std.stdio : writeln, writefln;
	enum testURL = URL("http://misc.herringway.pw/.test/");
	enum testURLHTTPS = URL("https://misc.herringway.pw/.test/");
	auto testHeaders = ["Referer": testURL.hostname];
	{
		auto req = get(testURL);
		req.md5 = "7528035a93ee69cedb1dbddb2f0bfcc8";
		version(online) {
			assertNotThrown(req.status, "MD5 failure (lowercase)");
			assert(req.isComplete);
		}
	}
	{
		auto req = get(testURLHTTPS);
		req.md5 = "7528035a93ee69cedb1dbddb2f0bfcc8";
		version(online) {
			assertNotThrown(req.status, "MD5 failure (lowercase, HTTPS)");
			assert(req.isComplete);
		}
	}
	{
		auto req = get(URL("https://expired.badssl.com"));
		version(online) {
			assertThrown(req.status, "HTTPS on expired cert succeeded");
		}
	}
	{
		auto req = get(URL("https://expired.badssl.com"));
		req.peerVerification = false;
		version(online) {
			assertNotThrown(req.status, "HTTPS without peer verification failed on expired cert");
		}
	}
	{
		auto req = get(testURL);
		req.md5 = "7528035A93EE69CEDB1DBDDB2F0BFCC8";
		version(online) {
			assertNotThrown(req.status, "MD5 failure (uppercase)");
			assert(req.isComplete);
		}
	}
	{
		auto req = get(testURL);
		req.sha1 = "f030bbbd32966cde41037b98a8849c46b76e4bc1";
		version(online) {
			assertNotThrown(req.status, "SHA1 failure (lowercase)");
			assert(req.isComplete);
		}
	}
	{
		auto req = get(testURL);
		req.sha1 = "F030BBBD32966CDE41037B98A8849C46B76E4BC1";
		version(online) {
			assertNotThrown(req.status, "SHA1 failure (uppercase)");
			assert(req.isComplete);
		}
	}
	{
		auto req = get(testURL);
		req.md5 = "7528035A93EE69CEDB1DBDDB2F0BFCC9";
		version(online) {
			assertThrown(req.status, "Bad MD5 (incorrect hash)");
		}
	}
	{
		auto req = get(testURL);
		assertThrown((req.md5 = ""), "Bad MD5 (empty string)");
	}
	{
		auto req = get(testURL);
		assertThrown((req.md5 = "BAD"), "Bad MD5 (BAD)");
	}
	{
		auto req = get(testURL);
		assertThrown((req.sha1 = "BAD"), "Bad SHA1 (BAD)");
	}
	{
		auto req = get(testURL);
		req.sha1 = "F030BBBD32966CDE41037B98A8849C46B76E4BC2";
		version(online) {
			assertThrown(req.status, "Bad SHA1 (incorrect hash)");
		}
	}
 	{
 		auto req = get(testURL);
 		req.expectedSize = 3;
		version(online) {
			assertNotThrown(req.status, "Expected size failure (correct size given)");
			assert(req.isComplete);
		}
 		req = get(testURL);
 		req.expectedSize = 4;
		version(online) {
			assertThrown(req.status, "Expected size failure (intentional bad size)");
		}
 	}
	{
		auto req = post(testURL, "hi");
		req.guaranteedData = true;
		version(online) {
			assertNotThrown(req.status);
			assert(req.isComplete);
			assert(req.content == "hi");
		}
	}
	{
		auto req = post(testURLHTTPS, "hi");
		req.guaranteedData = true;
		version(online) {
			assertNotThrown(req.status);
			assert(req.isComplete);
			assert(req.content == "hi");
		}
	}
	{
		auto req = post(testURLHTTPS, ["testparam": "hello"]);
		req.guaranteedData = true;
		version(online) {
			assertNotThrown(req.status);
			assert(req.isComplete);
			assert(req.content == "test param received");
		}
	}
	{
		auto req = post(testURLHTTPS, ["printparam": "hello&"]);
		req.guaranteedData = true;
		version(online) {
			assertNotThrown(req.status);
			assert(req.isComplete);
			assert(req.content == "hello&");
		}
	}
	{
		auto req = post(testURL, "");
		req.guaranteedData = true;
		version(online) {
			assertThrown(req.status);
		}
	}
	{
		auto req = get(testURL, testHeaders);
		version(online) {
			assert(req.content == "GET", "GET URL failure");
			assert(req.status == HTTPStatus.OK, "200 status undetected");
			assert(req.isComplete);
		}
	}
	version(online) {
		assertThrown(get(testURL.withParams(["403":""])).perform());
		assert(get(testURL.withParams(["403":""])).status == HTTPStatus.Forbidden, "403 error undetected");
		assertThrown(get(testURL.withParams(["404":""])).perform());
		assert(get(testURL.withParams(["404":""])).status == HTTPStatus.NotFound, "404 error undetected");
		assertThrown(get(testURL.withParams(["500":""])).perform());
		assert(get(testURL.withParams(["500":""])).status == HTTPStatus.InternalServerError, "500 error undetected");
		assert(post(testURL, "beep", testHeaders).content == "beep", "POST URL failed");
	}
	{
		auto req = get(testURL.withParams(["saveas":"example"]));
		version(online) {
			req.perform();
			assert(req.filename == "example", "content-disposition failure");
		}
	}
	{
		auto req = get(testURL.withParams(["PRINTHEADER": ""]));
		req.outHeaders["echo"] = "hello world";
		version(online) {
			assert(req.content == "hello world", "adding header failed");
		}
	}
	enum testDownloadURL = URL("http://misc.herringway.pw/whack.gif");
	auto a1 = get(testDownloadURL);
	version(online) {
		scope(exit) if (exists("whack.gif")) remove("whack.gif");
		scope(exit) if (exists("whack(2).gif")) remove("whack(2).gif");
		scope(exit) if (exists("whack2.gif")) remove("whack2.gif");
		a1.saveTo("whack.gif");
		assert(a1.saveTo("whack.gif", false).path == "whack(2).gif", "failure to rename file to avoid overwriting");
		a1.saveTo("whack2.gif");
	}
	auto resp1 = post(testURL.withParams(["1": ""]), "beep1");
	auto resp2 = post(testURL.withParams(["2": ""]), "beep2");
	version(online) {
		assert(resp2.content == "beep2");
		assert(resp2.content == "beep2");
		assert(resp1.content == "beep1");
	}
	{ //Oauth: header
		auto req = get(URL("http://term.ie/oauth/example/echo_api.php?success=true"));
		req.oauth(OAuthMethod.header, "key", "secret", "accesskey", "accesssecret");
		version(online) {
			assert(req.content == "success=true", "oauth failure:"~req.content);
			assert(req.status == HTTPStatus.OK, "OAuth failure");
		}
	}
	{ //Oauth: querystring
		auto req = get(URL("http://term.ie/oauth/example/echo_api.php?success=true"));
		req.oauth(OAuthMethod.queryString, "key", "secret", "accesskey", "accesssecret");
		version(online) {
			assert(req.content == "success=true", "oauth failure:"~req.content);
			assert(req.status == HTTPStatus.OK, "OAuth failure");
		}
	}
	{ //Cookies
		auto req = get(testURL.withParams(["printCookie": "testCookie"]));
		req.cookies ~= Cookie(".herringway.pw", "/", "testCookie", "something");
		version(online) {
			assert(req.content == "something");
		}
	}
	{ //BASIC Auth
		auto req = get(testURL);
		req.authorizationBasic("Test", "Password");
		version(online) {
			assert(req.content == "Test\nPassword");
		}
	}
}