module easyhttp.cache;

import std.conv;
import std.experimental.logger;
import std.file;
import std.path;
import std.utf;

import easyhttp.downloadmanager;
import easyhttp.fs;
import easyhttp.http;
import easyhttp.simple;
import easyhttp.url;

struct DownloadCache {
	string basePath;
	uint retries = 1;
	private RequestQueue downloader;

	this(string path) @safe {
		basePath = path;
	}
	this(RequestQueue manager) @safe {
		downloader = manager;
	}

	T get(T)(URL url, bool refresh = false) const {
		return get!T(getRequest(url), refresh);
	}
	T get(T)(const Request req, bool refresh = false) const {
		T convert(immutable(ubyte)[] data) @safe {
			static if (__traits(compiles, cast(T)data)) {
				return cast(T)data;
			} else {
				return data.to!T;
			}
		}
		auto path = getFilePath(req.url).toUTF8;
		if (path.exists) {
			tracef("%s (%s): found in cache", req.url, path);
			bool fetch = false;
			if (refresh) {
				const localLastModified = trustedTimeLastModified(path);
				const remoteLastModified = head(req.url).lastModified;
				if (remoteLastModified > localLastModified) {
					fetch = true;
					tracef("Remote has been modified since last fetch, refreshing (%s > %s)", remoteLastModified, localLastModified);
				}
			}
			if (!fetch) {
				return convert(trustedRead(path));
			}
		}
		tracef("%s (%s): fetching", req.url, path);
		uint retriesLeft = retries;
		do {
			retriesLeft--;
			try {
				auto data = req.perform.content!(immutable(ubyte)[]);
				mkdirRecurse(path.dirName);
				std.file.write(path, data);
				return convert(data);
			} catch(Exception e) {
				if (retriesLeft <= 0) {
					throw e;
				} else {
					tracef("%s (%s): retrying (%s)", req.url, path, e.msg);
				}
			}
		} while (retriesLeft > 0);
		assert(0);
	}
	immutable(ubyte)[] get(const Request req, bool refresh = false) const @safe {
		return get!(immutable(ubyte)[])(req, refresh);
	}

	void queue(Request req) @safe {
		string dest = getFilePath(req.url).toUTF8;
		if (dest.exists) {
			return;
		}
		QueuedRequest download;
		download.request = req;
		download.fileExistsAction = FileExistsAction.skip;
		download.destPath = dest;
		downloader.add(download);
	}
	void prepare() @safe pure {
		downloader.prepare();
	}
	void download() @system {
		downloader.download();
	}
	void perform() @system {
		downloader.perform();
	}

	auto getFilePath(const URL url) const @safe {
		return getRelativePath(basePath, url);
	}
	static auto getRelativePath(string base, const URL url) @safe {
		import std.algorithm.searching;
		const params = url.paramString;
		string path = url.path;
		skipOver(path, "/");
		while (path.endsWith("/")) {
			path = path[0 .. $ - 1];
		}
		string urlPath = (path == "" ? "index" : path);
		if ((urlPath.extension == ".") || (urlPath.extension == "")) {
			urlPath = setExtension(urlPath, "html");
		}
		if(params.length != 0) {
			urlPath ~= text("?", params);
		}
		version(Windows) {
			if (urlPath[$ - 1] == '.') {
				urlPath = urlPath[0 .. $ - 1] ~ "．";
			}
		}
		skipOver(urlPath, "/");
		return fixPath(buildNormalizedPath(base, url.hostname, urlPath), InvalidCharHandling.replaceUnicode);
	}
}

@safe unittest {
	import std.algorithm.comparison : equal;
	with (DownloadCache("tmp")) {
		assert(getFilePath(URL("http://example.com")).equal(buildNormalizedPath("tmp/example.com/index.html").asAbsolutePath));
		assert(getFilePath(URL(`http:\\example.com\somefile`)).equal(buildNormalizedPath("tmp/example.com/somefile.html").asAbsolutePath));
		assert(getFilePath(URL("http://example.com/somefile")).equal(buildNormalizedPath("tmp/example.com/somefile.html").asAbsolutePath));
		assert(getFilePath(URL("http://example.com/somefile.")).equal(buildNormalizedPath("tmp/example.com/somefile.html").asAbsolutePath));
		assert(getFilePath(URL("http://example.com/somefile.jpg")).equal(buildNormalizedPath("tmp/example.com/somefile.jpg").asAbsolutePath));
		assert(getFilePath(URL("http://example.com/some\0file.jpg")).equal(buildNormalizedPath("tmp/example.com/some␀file.jpg").asAbsolutePath));
		version(Windows) {
			assert(getFilePath(URL("http://example.com/index.php?hello=world")).equal(buildNormalizedPath("tmp/example.com/index.php？hello=world").asAbsolutePath));
			assert(getFilePath(URL("http://example.com/somefile?hello=world")).equal(buildNormalizedPath("tmp/example.com/somefile.html？hello=world").asAbsolutePath));
			assert(getFilePath(URL("http://example.com/somefile?hello=world.")).equal(buildNormalizedPath("tmp/example.com/somefile.html？hello=world．").asAbsolutePath));
		} else {
			assert(getFilePath(URL("http://example.com/index.php?hello=world")).equal(buildNormalizedPath("tmp/example.com/index.php?hello=world").asAbsolutePath));
			assert(getFilePath(URL("http://example.com/somefile?hello=world")).equal(buildNormalizedPath("tmp/example.com/somefile.html?hello=world").asAbsolutePath));
			assert(getFilePath(URL("http://example.com/somefile?hello=world.")).equal(buildNormalizedPath("tmp/example.com/somefile.html？hello=world.").asAbsolutePath));
		}
	}
}

@safe unittest {
	import std.algorithm.comparison : equal;
	assert(DownloadCache.getRelativePath("tmp", URL("http://example.com")).equal(buildNormalizedPath("tmp/example.com/index.html").asAbsolutePath));
	assert(DownloadCache.getRelativePath("tmp", URL("http://example.com/somefile")).equal(buildNormalizedPath("tmp/example.com/somefile.html").asAbsolutePath));
	assert(DownloadCache.getRelativePath("tmp", URL("http://example.com/somefile.jpg")).equal(buildNormalizedPath("tmp/example.com/somefile.jpg").asAbsolutePath));
	assert(DownloadCache.getRelativePath("tmp", URL("http://example.com/some\0file.jpg")).equal(buildNormalizedPath("tmp/example.com/some␀file.jpg").asAbsolutePath));
	version(Windows) {
		assert(DownloadCache.getRelativePath("tmp", URL("http://example.com/index.php?hello=world")).equal(buildNormalizedPath("tmp/example.com/index.php？hello=world").asAbsolutePath));
		assert(DownloadCache.getRelativePath("tmp", URL("http://example.com/somefile?hello=world")).equal(buildNormalizedPath("tmp/example.com/somefile.html？hello=world").asAbsolutePath));
	} else {
		assert(DownloadCache.getRelativePath("tmp", URL("http://example.com/index.php?hello=world")).equal(buildNormalizedPath("tmp/example.com/index.php?hello=world").asAbsolutePath));
		assert(DownloadCache.getRelativePath("tmp", URL("http://example.com/somefile?hello=world")).equal(buildNormalizedPath("tmp/example.com/somefile.html?hello=world").asAbsolutePath));
	}
	{
		auto url = URL("http://example.com");
		url.path = "/somefile.jpg";
		assert(DownloadCache.getRelativePath("tmp", url).equal(buildNormalizedPath("tmp/example.com/somefile.jpg").asAbsolutePath));
	}
	{
		auto url = URL("http://example.com");
		url.path = "/";
		assert(DownloadCache.getRelativePath("tmp", url).equal(buildNormalizedPath("tmp/example.com/index.html").asAbsolutePath));
	}
	{
		auto url = URL("http://example.com");
		url.path = "/somefile/";
		assert(DownloadCache.getRelativePath("tmp", url).equal(buildNormalizedPath("tmp/example.com/somefile.html").asAbsolutePath));
	}
}

@safe unittest {
	with(DownloadCache("tmp")) {
		get!(ubyte[])(URL("https://misc.herringway.pw/whack.gif"));
		get!(ubyte[])(URL("https://misc.herringway.pw/whack.gif"), true);
	}
}
