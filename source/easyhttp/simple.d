module easyhttp.simple;

import easyhttp.http;
import easyhttp.url;
import easyhttp.urlencoding;

auto getRequest(URL inURL, URLHeaders headers = URLHeaders.init) @safe pure {
	auto result = Request(inURL);
	result.method = HTTPMethod.get;
	try {
		foreach (k, v; headers) {
			result.addHeader(k, v);
		}
	} catch (Exception) {
		assert(0, "Iterating through headers caused exception?");
	}
	return result;
}
@safe pure nothrow unittest {
	auto get1 = getRequest(URL(URL.Proto.HTTPS, "localhost"));
	auto get2 = getRequest(URL(URL.Proto.HTTPS, "localhost"), ["":""]);
}
auto get(URL inURL, URLHeaders headers = URLHeaders.init) {
	return getRequest(inURL, headers).perform();
}
auto postRequest(U)(URL inURL, U data, URLHeaders headers = URLHeaders.init) if (isURLEncodable!U || is(U == POSTData)) {
	auto result = Request(inURL);
	result.method = HTTPMethod.post;
	result.setPOSTData(data);
	foreach (k, v; headers) {
		result.addHeader(k, v);
	}
	return result;
}
@safe pure unittest {
	auto post1 = postRequest(URL(URL.Proto.HTTPS, "localhost"), "");
	auto post2 = postRequest(URL(URL.Proto.HTTPS, "localhost"), "", ["":""]);
	auto post3 = postRequest(URL(URL.Proto.HTTPS, "localhost"), ["":""], ["":""]);
	auto post4 = postRequest(URL(URL.Proto.HTTPS, "localhost"), ["":[""]], ["":""]);
}
auto post(U)(URL inURL, U data, URLHeaders headers = URLHeaders.init) if (isURLEncodable!U || is(U == POSTData)) {
	return postRequest(inURL, data, headers).perform();
}

/++
 + A useless HTTP request for testing
 +/
auto nullRequest() @safe {
	return getRequest(URL(URL.Proto.HTTP, "localhost", "/"));
}
