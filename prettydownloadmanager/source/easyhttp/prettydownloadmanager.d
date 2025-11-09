module easyhttp.prettydownloadmanager;

import progresso;
import easyhttp.cache;
import easyhttp.downloadmanager;
import easyhttp.http;

import std.logger;

struct PrettyDownloadManager {
	private RequestQueue manager;
	private ProgressTracker progressTracker;
	private bool loaded;
	bool noColours;

	void showTotal() nothrow @safe pure {
		progressTracker.showTotal = true;
		progressTracker.totalItemsOnly = true;
	}
	bool pathAlreadyInQueue(const string path) nothrow @safe {
		return manager.pathAlreadyInQueue(path);
	}
	auto add(const QueuedRequest request) @safe {
		return manager.add(request);
	}
	void prepare() @safe pure {
		manager.prepare();
		prepareBars();
	}
	void download(bool throwOnError = true) @system {
		prepareBars();
		manager.onProgress = (request, queueDetails, progress) @safe {
			import std.algorithm.comparison : among;
			import std.conv : text;
			if (progress.state == QueueItemState.starting) {
				progressTracker.setItemActive(queueDetails.id);
			}
			progressTracker.setItemMaximum(queueDetails.id, progress.size);
			progressTracker.setItemProgress(queueDetails.id, progress.downloaded);
			if (progress.state == QueueItemState.error) {
				progressTracker.setItemStatus(queueDetails.id, text(progress.state, " - ", progress.error.msg));
				if (!noColours) {
					progressTracker.setItemColours(queueDetails.id, RGB(255, 0, 0), RGB(0, 0, 0), ColourMode.unchanging);
				}
			} else {
				progressTracker.setItemStatus(queueDetails.id, progress.state.text);
			}
			if (progress.state.among(QueueItemState.complete, QueueItemState.error)) {
				progressTracker.completeItem(queueDetails.id);
			}
			progressTracker.updateDisplay();
		};
		manager.download(throwOnError);
		progressTracker.clear();
		loaded = false;
	}
	void preDownloadFunction(typeof(manager.preDownloadFunction) dg) @safe {
		manager.preDownloadFunction = dg;
	}
	void postDownloadFunction(typeof(manager.postDownloadFunction) dg) @safe {
		manager.postDownloadFunction = dg;
	}
	void postDownloadCheck(typeof(manager.postDownloadCheck) dg) @safe {
		manager.postDownloadCheck = dg;
	}
	void onError(typeof(manager.onError) dg) @safe {
		manager.onError = dg;
	}
	auto ref delay() @safe => manager.delay;
	auto ref generateName() @safe => manager.generateName;
	auto ref queueCount() @safe => manager.queueCount;
	private void prepareBars() @safe pure {
		import std.conv : text;
		if (!loaded) {
			foreach (id, request; manager.queue) {
				progressTracker.addNewItem(id);
				progressTracker.setItemName(id, request.label ? request.label : request.request.url.text);
				if (!noColours) {
					progressTracker.setItemColours(id, RGB(0, 255, 0), RGB(0, 0, 0), ColourMode.unchanging);
				}
			}
			loaded = true;
		}
	}
}

@system unittest {
	import easyhttp.url : URL;
	import easyhttp.simple : getRequest;
	import std.file : exists, remove;
	import std.conv : text;
	with(PrettyDownloadManager()) {
		showTotal();
		foreach (i; 0 .. 100) {
			auto dlReq = QueuedRequest();
			dlReq.request = getRequest(URL("https://misc.herringway.pw/whack.gif"));
			dlReq.destPath = text("whack", i, ".gif");
			dlReq.postDownload = (r, r2, q) {
				remove(r.destPath);
			};
			add(dlReq);
		}
		//version(online) {
			download();
		//}
	}
}

struct PrettyDownloadCache {
	private DownloadCache manager;
	private ProgressTracker progressTracker;
	private bool loaded;
	bool noColours;

	this(string path) @safe {
		manager = DownloadCache(path);
	}
	private this(DownloadCache cache) @safe pure {
		manager = cache;
	}
	void showTotal() nothrow @safe pure {
		progressTracker.showTotal = true;
		progressTracker.totalItemsOnly = true;
	}
	auto add(Request request) @safe {
		return manager.queue(request);
	}
	auto add(QueuedRequest request) @safe {
		return manager.queue(request);
	}
	void prepare() @safe pure {
		manager.prepare();
		prepareBars();
	}
	void download(bool throwOnError = true) @system {
		prepareBars();
		manager.onProgress = (in QueuedRequest request, in QueueDetails queueDetails, in QueueItemProgress progress) @safe {
			import std.algorithm.comparison : among;
			import std.conv : text;
			if (progress.state == QueueItemState.starting) {
				progressTracker.setItemActive(queueDetails.id);
			}
			progressTracker.setItemMaximum(queueDetails.id, progress.size);
			progressTracker.setItemProgress(queueDetails.id, progress.downloaded);
			if (progress.state == QueueItemState.error) {
				progressTracker.setItemStatus(queueDetails.id, text(progress.state, " - ", progress.error.msg));
				if (!noColours) {
					progressTracker.setItemColours(queueDetails.id, RGB(255, 0, 0), RGB(0, 0, 0), ColourMode.unchanging);
				}
			} else {
				progressTracker.setItemStatus(queueDetails.id, progress.state.text);
			}
			if (progress.state.among(QueueItemState.complete, QueueItemState.error, QueueItemState.skipping)) {
				progressTracker.completeItem(queueDetails.id);
			}
			progressTracker.updateDisplay();
		};
		manager.download(throwOnError);
		progressTracker.clear();
		loaded = false;
	}
	bool pathAlreadyInQueue(const string path) nothrow @safe => manager.pathAlreadyInQueue(path);
	auto ref queueCount() @safe => manager.queueCount;
	auto ref preDownloadFunction() @safe => manager.preDownloadFunction;
	auto ref postDownloadFunction() @safe => manager.postDownloadFunction;
	auto ref onError() @safe => manager.onError;
	static PrettyDownloadCache systemCache() @safe => PrettyDownloadCache(DownloadCache.systemCache);
	private void prepareBars() @safe pure {
		import std.conv : text;
		if (!loaded) {
			foreach (id, request; manager.queue) {
				progressTracker.addNewItem(id);
				progressTracker.setItemName(id, request.label ? request.label : request.request.url.text);
				if (!noColours) {
					progressTracker.setItemColours(id, RGB(0, 255, 0), RGB(0, 0, 0), ColourMode.unchanging);
				}
			}
			loaded = true;
		}
	}
}
