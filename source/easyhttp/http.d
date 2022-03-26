module easyhttp.http;

import core.time;

import std.algorithm;
import std.array;
import std.base64;
import std.conv;
import std.datetime;
import std.digest;
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

enum reqsVerboseLevel = 4;
debug(verbosehttp) {
	enum verboseDefault = true;
} else {
	enum verboseDefault = false;
}


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
	void toString(T)(T sink) const if (isOutputRange!(T, char[])) {
		import std.format : formattedWrite;
		sink.formattedWrite!"%s=%s"(key, value);
	}
}

struct HTTPHeader {
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

enum POSTDataType {
	none,
	raw,
	form
}

///Action to take when saving a file that already exists
enum FileExistsAction {
	skip,
	overwrite,
	rename
}

/++
 + An HTTP Request.
 +/
struct Request {
	private struct OAuthParams {
		string consumerToken;
		string consumerSecret;
		string token;
		string tokenSecret;
	}
	private string bearerToken;
	private Nullable!size_t sizeExpected;
	private bool checkNoContent = false;
	bool ignoreSizeMismatch = true;
	///Maximum time to wait for the request to complete
	Duration timeout = dur!"minutes"(5);
	///The URL being requested
	URL url;
	package HTTPMethod method;
	private immutable(HTTPHeader)[] outHeaders;
	private Nullable!OAuthParams oAuthParams;
	///Certificate root store
	Nullable!string certPath;
	///Whether or not to ignore errors in the server's SSL certificate
	bool ignoreHostCert = false;
	///Whether or not to verify the certificate for HTTPS connections
	bool peerVerification = true;
	///Whether to output verbose debugging information to stdout
	bool verbose = verboseDefault;
	string contentType = "application/octet-stream";
	Cookie[] cookies;
	private POSTDataType postDataType;
	private QueryParameter[] formPOSTData;
	private immutable(ubyte)[] rawPOSTData;

	//private Nullable!string outFile;
	invariant() {
		assert(url.protocol.among(URL.Proto.HTTP, URL.Proto.HTTPS), "Invalid protocol specified in URL \""~url.text~"\"");
	}
	private this(immutable typeof(this.tupleof) fields) immutable @safe pure nothrow {
		this.tupleof = fields;
	}
	this(URL initial) @safe pure nothrow {
		outHeaders ~= HTTPHeader("User-Agent", packageName ~ " " ~ packageVersion);
		url = initial;
	}
	/++
	 + The default filename for the file being requested.
	 +/
	string filename() @safe nothrow const pure {
		return url.fileName;
	}
	/++
	 + Whether or not this request should fail upon receiving an empty body.
	 +/
	ref bool guaranteedData() return @safe pure nothrow @nogc {
		return checkNoContent;
	}
	/++
	 + Adds an outgoing header to the request.
	 +
	 + No effect on completed requests.
	 +/
	void addHeader(string key, string val) @safe pure nothrow {
		outHeaders ~= HTTPHeader(key, val);
	}
	/++
	 + Adds an OAuth bearer token to the request.
	 +
	 + Valid methods are OAuthMethod.header.
	 +/
	void oAuthBearer(in string token, OAuthMethod method = OAuthMethod.header) @safe {
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
		string[string] params;
		auto copy_url = URL(url.protocol, url.hostname, url.path, url.params);
		params["oauth_consumer_key"] = copy_url.params["oauth_consumer_key"] = oAuthParams.get.consumerToken;
		params["oauth_token"] = copy_url.params["oauth_token"] = oAuthParams.get.token;
		params["oauth_nonce"] = copy_url.params["oauth_nonce"] = uniform(uint.min, uint.max).text ~ Clock.currTime().stdTime.text;
		params["oauth_signature_method"] = copy_url.params["oauth_signature_method"] = "HMAC-"~hashType;
		params["oauth_timestamp"] = copy_url.params["oauth_timestamp"] = Clock.currTime().toUTC().toUnixTime().text;
		params["oauth_version"] = copy_url.params["oauth_version"] = "1.0";
		string signature = [encodeComponentSafe(oAuthParams.get.consumerSecret), encodeComponentSafe(oAuthParams.get.tokenSecret)].join("&");
		auto signer = HMAC!Hash(signature.representation);
		auto baseString = only(encodeComponentSafe(method.text.toUpper()), encodeComponentSafe(copy_url.format!"%n"), encodeComponentSafe(copy_url.paramString)).map!representation.joiner("&".representation);

		put(signer, baseString);

		params["oauth_signature"] = Base64.encode(signer.finish());
		params["realm"] = "";
		if (oauthMethod == OAuthMethod.header) {
			string[] authString;
			foreach (k, v; params) {
				authString ~= format(`%s="%s"`, k, encodeComponentSafe(v).replace("+", "%2B"));
			}
			addHeader("Authorization", "OAuth " ~ authString.join(", "));
		}
		if (oauthMethod == OAuthMethod.queryString) {
			url.params["oauth_version"] = "1.0";
			url.params["oauth_signature"] = params["oauth_signature"];
			url.params["oauth_signature_method"] = params["oauth_signature_method"];
			url.params["oauth_nonce"] = params["oauth_nonce"];
			url.params["oauth_timestamp"] = params["oauth_timestamp"];
			url.params["oauth_consumer_key"] = params["oauth_consumer_key"];
			url.params["oauth_token"] = params["oauth_token"];
		}
	}

	void authorizationBasic(string user, string pass) @safe {
		addHeader("Authorization", "Basic "~Base64.encode((user~":"~pass).representation).idup);
	}
	/++
	 + The expected size of the body if available.
	 +
	 + Null if no size is known.
	 +/
	ref Nullable!size_t expectedSize() return @safe nothrow pure @nogc {
		return sizeExpected;
	}
	alias Hash(T) = Nullable!(char[2*digestLength!T]);
	Hash!MD5 expectedMD5;
	Hash!SHA1 expectedSHA1;
	Hash!SHA256 expectedSHA256;
	Hash!SHA384 expectedSHA384;
	Hash!SHA512 expectedSHA512;
	/++
	 + Whether or not to ignore errors in the server's SSL certificate.
	 +/
	ref bool ignoreHostCertificate() return @nogc @safe pure nothrow {
		return ignoreHostCert;
	}

	void setPOSTData(immutable ubyte[] data) @safe @nogc pure nothrow {
		this.rawPOSTData = data;
		this.postDataType = POSTDataType.raw;
	}
	void setPOSTData(string data) @safe pure nothrow {
		setPOSTData(data.representation);
	}
	void setPOSTData(T)(T data) @safe pure if (isURLEncodable!T) {
		this.formPOSTData = urlEncode(data);
		this.postDataType = POSTDataType.form;
	}
	/++
	 + Performs the request.
	 +/
	auto perform() const @safe {
		import vibe.http.client;
		import vibe.utils.dictionarylist;
		import vibe.stream.operations;
		import vibe.stream.tls;
		Response response;
		auto settings = new HTTPClientSettings;
		if (!certPath.isNull) {
			enforce(certPath.get.exists, "Certificate path not found");
		}
		TLSPeerValidationMode* validation = new TLSPeerValidationMode((peerVerification ? TLSPeerValidationMode.checkTrust : 0) | (ignoreHostCert ? 0 : TLSPeerValidationMode.validCert));
		settings.tlsContextSetup = (scope TLSContext context) @safe {
			try {
				if (!systemCertPath.isNull) {
					context.useTrustedCertificateFile(systemCertPath.get);
				}
				context.peerValidationMode = *validation;
			} catch (Exception) {}
		};
		string tmpURL = url.text;
		foreach (i; 0 .. 10) {
			requestHTTP(tmpURL,
				(scope HTTPClientRequest req) {
					alias VibeHTTPMethod = vibe.http.common.HTTPMethod;
					final switch (method) {
						case HTTPMethod.post:
							req.method = VibeHTTPMethod.POST;
							final switch (postDataType) {
								case POSTDataType.none:
									break;
								case POSTDataType.form:
									DictionaryList!string form;
									foreach (param; formPOSTData) {
										form[param.key] = param.value;
									}
									req.writeFormBody(form.byKeyValue);
									break;
								case POSTDataType.raw:
									req.writeBody(rawPOSTData, contentType);
									break;
							}
							break;
						case HTTPMethod.get:
							req.method = VibeHTTPMethod.GET;
							break;
						case HTTPMethod.head:
							req.method = VibeHTTPMethod.HEAD;
							break;
						case HTTPMethod.put, HTTPMethod.delete_, HTTPMethod.trace, HTTPMethod.options, HTTPMethod.connect, HTTPMethod.patch:
							assert(0, "Unimplemented");
					}
					foreach (header; outHeaders) {
						req.headers[header.key] = header.value;
					}
					req.headers.addField("Cookie", format!"%-(%s; %)"(cookies));
				},
				(scope HTTPClientResponse res) {
					if (method != HTTPMethod.head) {
						response._content = assumeUnique(res.bodyReader.readAll());
					}
					response.statusCode = cast(HTTPStatus)res.statusCode;
					foreach (key, value; res.headers.byKeyValue) {
						response.headers ~= HTTPHeader(key, value);
						switch (key.toLower) {
							case "content-disposition":
								immutable disposition = parseDispositionString(value);
								if (!disposition.filename.isNull) {
									response.overriddenFilename = disposition.filename.get;
								}
								break;
							case "content-md5":
								enforce(response.md5 == toHexString(Base64.decode(value)), new HashException("MD5", response.md5, toHexString(Base64.decode(value))));
								break;
							case "content-length":
								enforce(ignoreSizeMismatch || (response._content.length == value.to!size_t), new HTTPException(format!"Content length mismatched (%s vs %s)"(response._content.length, value.to!size_t)));
								break;
							case "location":
								tmpURL = value;
								break;
							default: break;
						}
					}
					foreach (key, cookie; res.cookies.byKeyValue) {
						response.outCookies ~= Cookie(cookie.domain, cookie.path, key, cookie.value);
					}
				},
			settings);
			if (!response.statusCode.among(HTTPStatus.MovedPermanently, HTTPStatus.Found, HTTPStatus.SeeOther, HTTPStatus.TemporaryRedirect)) {
				break;
			}
		}
		enforce(response.statusCode != 0, new HTTPException("No status code received"));
		if (!expectedMD5.isNull) {
			enforce(icmp(expectedMD5.get, response.md5) == 0, new HashException("MD5", expectedMD5.get, response.md5));
		}
		if (!expectedSHA1.isNull) {
			enforce(icmp(expectedSHA1.get, response.sha1) == 0, new HashException("SHA1", expectedSHA1.get, response.sha1));
		}
		if (!expectedSHA256.isNull) {
			enforce(icmp(expectedSHA256.get, response.sha256) == 0, new HashException("SHA256", expectedSHA256.get, response.sha256));
		}
		if (!expectedSHA384.isNull) {
			enforce(icmp(expectedSHA384.get, response.sha384) == 0, new HashException("SHA384", expectedSHA384.get, response.sha384));
		}
		if (!expectedSHA512.isNull) {
			enforce(icmp(expectedSHA512.get, response.sha512) == 0, new HashException("SHA512", expectedSHA512.get, response.sha512));
		}
		if (!sizeExpected.isNull) {
			enforce(response._content.length == sizeExpected.get, new HTTPException("Size of data mismatched expected size"));
		}
		if (checkNoContent) {
			enforce(response._content.length > 0, new HTTPException("No data received"));
		}
		return response;
	}
	/++
	 + Saves the body of this request to a local path.
	 +
	 + Will not overwrite existing files unless overwrite is set.
	 +
	 + Params:
	 +  fullPath = default destination for the file to be saved
	 +  overwrite = whether or not to overwrite existing files
	 +/
	SavedFileInformation saveTo(string fullPath, FileExistsAction fileExistsAction = FileExistsAction.rename) const @safe {
		SavedFileInformation output;
		auto response = perform();
		output.response = response;
		if (fullPath.exists) {
			final switch (fileExistsAction) {
				case FileExistsAction.rename:
					while (fullPath.exists) {
						fullPath = fullPath.duplicateName;
					}
					break;
				case FileExistsAction.skip:
					return output;
				case FileExistsAction.overwrite:
					output.overwritten = true;
					break;
			}
		}
		output.path = fullPath;
		if (!fullPath.dirName.exists) {
			mkdirRecurse(fullPath.dirName());
		}
		auto writeFile = File(fullPath, "wb");

		scope(exit) {
			if (writeFile.isOpen) {
				writeFile.flush();
				writeFile.close();
			}
		}
		writeFile.trustedRawWrite(response._content);
		return output;
	}
	auto finalized() const {
		return immutable Request(
			bearerToken,
			sizeExpected,
			checkNoContent,
			ignoreSizeMismatch,
			timeout,
			url.idup,
			method,
			outHeaders,
			oAuthParams,
			certPath,
			ignoreHostCert,
			peerVerification,
			verbose,
			contentType,
			cookies.idup,
			postDataType,
			formPOSTData.idup,
			rawPOSTData,
			expectedMD5,
			expectedSHA1,
			expectedSHA256,
			expectedSHA384,
			expectedSHA512,
		);
	}
}
/++
 + Information about a file saved with the saveTo function.
 +/
struct SavedFileInformation {
	///Path that was used for actually saving the file.
	string path;
	///Response received from server
	Response response;
	///Whether or not the file was overwritten
	bool overwritten;
}

struct Response {
	private immutable(ubyte)[] _content;
	///The HTTP status code last seen
	HTTPStatus statusCode;
	immutable(HTTPHeader)[] headers;
	immutable(Cookie)[] outCookies;
	///Change filename for saved files
	string overriddenFilename;
	alias md5 = hash!MD5;
	alias sha1 = hash!SHA1;
	alias sha256 = hash!SHA256;
	alias sha384 = hash!SHA384;
	alias sha512 = hash!SHA512;
	private template hash(HashMethod) {
		/++
		 + Gets the hash of the request body.
		 +
		 + Empty if request is incomplete.
		 +/
		public string hash() @safe pure nothrow const {
			return getHash!HashMethod;
		}
	}
	private string getHash(HashMethod)() pure nothrow const if(isDigest!HashMethod) {
		auto hash = makeDigest!HashMethod;
		hash.put(_content);
		return hash.finish().toHexString!(Order.increasing, LetterCase.upper);
	}
	/++
	 + The HTTP status code for a completed request.
	 +
	 + Completes the request if not already done.
	 +/
	HTTPStatus status() @safe {
		return statusCode;
	}
	/++
	 + Finds matching headers
	 +/
	 auto matchingHeaders(string key) inout {
		return headers.filter!(x => x.key == key)();
	 }
	/++
	 + Returns body of response as a string.
	 +/
	T content(T = string)() {
		return contentInternal!T;
	}
	///ditto
	 T content(T = string)() const {
		return contentInternal!T;
	 }

	 private T contentInternal(T = string)() const {
		static if (is(T == string)) {
			return _content.assumeUTF;
		} else {
			return _content.to!T;
		}
	 }
	 SysTime lastModified() const @safe {
		auto lastModifiedHeader = matchingHeaders("Last-Modified");
		if (lastModifiedHeader.empty) {
			return SysTime.min;
		}
		return parseLastModified(lastModifiedHeader.front.value);
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
	this(HTTPStatus errorCode, const URL url, string file = __FILE__, size_t line = __LINE__) {
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
	this(const(char)[] hashType, const(char)[] badHash, string goodHash, string file = __FILE__, size_t line = __LINE__) @safe pure
		in(goodHash != badHash, "Good hash and mismatched hash match!")
	{
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
@safe unittest {
	import easyhttp.simple : getRequest, postRequest;
	import std.exception : assertNotThrown, assertThrown;
	import std.file : remove, exists;
	import std.stdio : writeln, writefln;
	enum testURL = URL("http://misc.herringway.pw/.test/");
	enum testURLHTTPS = URL("https://misc.herringway.pw/.test/");
	auto testHeaders = ["Referer": testURL.hostname];
	{
		auto req = getRequest(testURL);
		req.expectedMD5 = "7528035a93ee69cedb1dbddb2f0bfcc8";
		version(online) with (req.perform()) {
			assert(status == 200);
		}
	}
	{
		auto req = getRequest(testURLHTTPS);
		req.expectedMD5 = "7528035a93ee69cedb1dbddb2f0bfcc8";
		version(online) with (req.perform()) {
			assert(status == 200);
		}
	}
	{
		auto req = getRequest(URL("https://self-signed.badssl.com/"));
		version(online) {
			assertThrown(req.perform(), "HTTPS on untrusted cert succeeded");
		}
	}
	{
		auto req = getRequest(URL("https://expired.badssl.com"));
		version(online) {
			assertThrown(req.perform(), "HTTPS on expired cert succeeded");
		}
	}
	{
		auto req = getRequest(testURL);
		req.expectedMD5 = "7528035A93EE69CEDB1DBDDB2F0BFCC8";
		version(online) {
			assertNotThrown(req.perform(), "MD5 failure (uppercase)");
		}
	}
	{
		auto req = getRequest(testURL);
		req.expectedSHA1 = "f030bbbd32966cde41037b98a8849c46b76e4bc1";
		version(online) {
			assertNotThrown(req.perform(), "SHA1 failure (lowercase)");
		}
	}
	{
		auto req = getRequest(testURL);
		req.expectedSHA1 = "F030BBBD32966CDE41037B98A8849C46B76E4BC1";
		version(online) {
			assertNotThrown(req.perform(), "SHA1 failure (uppercase)");
		}
	}
	{
		auto req = getRequest(testURL);
		req.expectedMD5 = "7528035A93EE69CEDB1DBDDB2F0BFCC9";
		version(online) {
			assertThrown(req.perform(), "Bad MD5 (incorrect hash)");
		}
	}
	{
		auto req = getRequest(testURL);
		req.expectedSHA1 = "F030BBBD32966CDE41037B98A8849C46B76E4BC2";
		version(online) {
			assertThrown(req.perform(), "Bad SHA1 (incorrect hash)");
		}
	}
 	{
		auto req = getRequest(testURL);
		req.expectedSize = 3;
		version(online) {
			assertNotThrown(req.perform(), "Expected size failure (correct size given)");
		}
		req = getRequest(testURL);
		req.expectedSize = 4;
		version(online) {
			assertThrown(req.perform(), "Expected size failure (intentional bad size)");
		}
 	}
	{
		auto req = postRequest(testURL, "hi");
		req.guaranteedData = true;
		version(online) with (req.perform()) {
			assert(content == "hi");
		}
	}
	{
		auto req = postRequest(testURLHTTPS, "hi");
		req.guaranteedData = true;
		version(online) with (req.perform()) {
			assert(content == "hi");
		}
	}
	{
		auto req = postRequest(testURLHTTPS, ["testparam": "hello"]);
		req.guaranteedData = true;
		version(online) with (req.perform()) {
			assert(content == "test param received");
		}
	}
	{
		auto req = postRequest(testURLHTTPS, ["printparam": "hello&"]);
		req.guaranteedData = true;
		version(online) with (req.perform()) {
			assert(content == "hello&");
		}
	}
	{
		auto req = postRequest(testURL, "");
		req.guaranteedData = true;
		version(online) {
			assertThrown(req.perform());
		}
	}
	{
		auto req = getRequest(testURL, testHeaders);
		version(online) with (req.perform()) {
			assert(content == "GET");
			assert(status == HTTPStatus.OK);
		}
	}
	version(online) {
		with(getRequest(testURL.withReplacedParams(["403":""])).perform()) {
			assert(status == HTTPStatus.Forbidden);
		}
		with(getRequest(testURL.withReplacedParams(["404":""])).perform()) {
			assert(status == HTTPStatus.NotFound);
		}
		with(getRequest(testURL.withReplacedParams(["500":""])).perform()) {
			assert(status == HTTPStatus.InternalServerError);
		}
		with(postRequest(testURL, "beep", testHeaders).perform()) {
			assert(content == "beep");
		}
	}
	{
		auto req = getRequest(testURL.withReplacedParams(["saveas":"example"]));
		version(online) {
			with(req.perform()) {
				assert(overriddenFilename == "example", "content-disposition failure");
			}
		}
	}
	{
		auto req = getRequest(testURL.withReplacedParams(["PRINTHEADER": ""]));
		req.addHeader("echo", "hello world");
		version(online) with (req.perform()) {
			assert(content == "hello world");
		}
	}
	enum testDownloadURL = URL("http://misc.herringway.pw/whack.gif");
	auto a1 = getRequest(testDownloadURL);
	version(online) {
		scope(exit) if (exists("whack.gif")) remove("whack.gif");
		scope(exit) if (exists("whack(2).gif")) remove("whack(2).gif");
		scope(exit) if (exists("whack2.gif")) remove("whack2.gif");
		a1.saveTo("./whack.gif");
		a1.saveTo("./whack2.gif");
	}

	{ //Oauth: header
		auto req = getRequest(URL("https://misc.herringway.pw/.test/oauth/examples/echo_api.php?success=true"));
		req.oauth(OAuthMethod.header, "key", "secret", "accesskey", "accesssecret");
		version(online) with (req.perform()) {
			assert(content == "success=true", "oauth failure:"~content);
			assert(status == HTTPStatus.OK, "OAuth failure");
		}
	}
	{ //Oauth: querystring
		auto req = getRequest(URL("https://misc.herringway.pw/.test/oauth/examples/echo_api.php?success=true"));
		req.oauth(OAuthMethod.queryString, "key", "secret", "accesskey", "accesssecret");
		version(online) with (req.perform()) {
			assert(content == "success=true", "oauth failure:"~content);
			assert(status == HTTPStatus.OK, "OAuth failure");
		}
	}
	{ //Cookies
		auto req = getRequest(testURL.withReplacedParams(["printCookie": "testCookie"]));
		req.cookies ~= Cookie(".herringway.pw", "/", "testCookie", "something");
		version(online) with (req.perform()) {
			assert(content == "something");
		}
	}
	{ //BASIC Auth
		auto req = getRequest(testURL);
		req.authorizationBasic("Test", "Password");
		version(online) with (req.perform()) {
			assert(content == "Test\nPassword");
		}
	}
}

SysTime parseLastModified(const(char)[] str) @safe {
	import std.format : formattedRead;
	static immutable months = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
	string dummy, month;
	int day, year, hour, minute, second;
	formattedRead(str, "%s, %d %s %d %d:%d:%d GMT", dummy, day, month, year, hour, minute, second);
	return SysTime(DateTime(year, cast(int)months.countUntil(month), day, hour, minute, second), UTC());
}

@safe unittest {
	import std.exception : assertThrown;
	assert(parseLastModified("Wed, 21 Oct 2015 07:28:00 GMT") == SysTime(DateTime(2015, 10, 21, 7, 28, 0), UTC()));
	assertThrown(parseLastModified("idk"));
}
