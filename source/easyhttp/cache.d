module easyhttp.cache;

import std.conv;
import std.experimental.logger;
import std.file;
import std.path;
import std.utf;

import easyhttp.config;
import easyhttp.downloadmanager;
import easyhttp.fs;
import easyhttp.http;
import easyhttp.simple;
import easyhttp.url;

struct DownloadCache {
	string basePath;
	uint retries = 1;
	package RequestQueue downloader;

	this(string path) @safe
	in(path != "", "Path cannot be blank")
	{
		basePath = path;
	}
	this(RequestQueue manager) @safe {
		downloader = manager;
	}

	immutable(ubyte)[] get(const Request req, bool refresh = false) const @safe {
		return get(req, getFilePath(req.url).toUTF8, refresh);
	}
	immutable(ubyte)[] get(const Request req, string path, bool refresh = false) const @safe {
		import std.datetime.systime : SysTime;
		import std.exception : enforce;
		if (path.exists) {
			tracef("%s (%s): found in cache", req.url, path);
			bool fetch = false;
			if (refresh) {
				const localLastModified = trustedTimeLastModified(path);
				const remoteLastModified = head(req.url).lastModified;
				if (remoteLastModified > localLastModified) {
					fetch = true;
					tracef("Remote has been modified since last fetch, refreshing (%s > %s)", remoteLastModified, localLastModified);
				} else if (remoteLastModified == SysTime.min) {
					fetch = true;
					trace("Remote has no modified header. Refreshing anyway.");
				} else {
					tracef("Remote has not been modified since last fetch, not refreshing (%s <= %s)", remoteLastModified, localLastModified);
				}
			}
			if (!fetch) {
				return trustedRead(path);
			}
		}
		tracef("%s (%s): fetching", req.url, path);
		uint retriesLeft = retries;
		do {
			retriesLeft--;
			try {
				auto resp = req.perform();
				enforce((resp.statusCode >= HTTPStatus.OK) && (resp.statusCode < HTTPStatus.MultipleChoices), new StatusException(resp.statusCode, req.url));
				auto data = resp.content!(immutable(ubyte)[]);
				mkdirRecurse(path.dirName);
				std.file.write(path, data);
				return data;
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

	void queue(QueuedRequest req) @safe {
		import std.exception : enforce;
		enforce(!req.destPath, "Download path already set");
		req.destPath = getFilePath(req.request.url).toUTF8;
		if (req.destPath.exists) {
			return;
		}
		downloader.add(req);
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
	static auto systemCache() @safe {
		return DownloadCache(settings.systemCachePath);
	}
	bool pathAlreadyInQueue(const string path) @safe nothrow {
		return downloader.pathAlreadyInQueue(path);
	}
	void onProgress(typeof(downloader.onProgress) dg) @safe nothrow {
		downloader.onProgress = dg;
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
		get(getRequest(URL("https://misc.herringway.pw/whack.gif")));
		get(getRequest(URL("https://misc.herringway.pw/whack.gif")), true);
	}
}
