module easyhttp.prettydownloadmanager;

import progresso.progresstracker;
import easyhttp.cache;
import easyhttp.downloadmanager;
import easyhttp.http;

import std.experimental.logger;

struct PrettyDownloadManager {
	private RequestQueue manager;
	private ProgressTracker progressTracker;
	private bool loaded;

	void showTotal() nothrow @safe pure {
		progressTracker.showTotal = true;
		progressTracker.totalItemsOnly = true;
	}
	bool pathAlreadyInQueue(const string path) nothrow @safe {
		return manager.pathAlreadyInQueue(path);
	}
	void add(const QueuedRequest request) @safe {
		manager.add(request);
	}
	void prepare() @safe pure {
		manager.prepare();
		prepareBars();
	}
	void download(bool throwOnError = true) @system {
		prepareBars();
		manager.onProgress = (request, queueDetails, progress) @safe {
			import std.conv : text;
			if (progress.state == QueueItemState.starting) {
				progressTracker.setItemActive(queueDetails.ID);
			}
			progressTracker.setItemMaximum(queueDetails.ID, progress.size);
			progressTracker.setItemProgress(queueDetails.ID, progress.downloaded);
			if (progress.state == QueueItemState.error) {
				progressTracker.setItemStatus(queueDetails.ID, text(progress.state, " - ", progress.error.msg));
			} else {
				progressTracker.setItemStatus(queueDetails.ID, progress.state.text);
			}
			if (progress.state == QueueItemState.complete) {
				progressTracker.completeItem(queueDetails.ID);
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
	void onError(typeof(manager.onError) dg) @safe {
		manager.onError = dg;
	}
	auto ref queueCount() @safe {
		return manager.queueCount;
	}
	private void prepareBars() @safe pure {
		import std.conv : text;
		if (!loaded) {
			foreach (id, request; manager.queue) {
				progressTracker.addNewItem(id);
				progressTracker.setItemName(id, request.label ? request.label : request.request.url.text);
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
	bool pathAlreadyInQueue(const string path) nothrow @safe {
		return manager.pathAlreadyInQueue(path);
	}
	void add(Request request) @safe {
		manager.queue(request);
	}
	void add(QueuedRequest request) @safe {
		manager.queue(request);
	}
	void prepare() @safe pure {
		manager.prepare();
		prepareBars();
	}
	void download(bool throwOnError = true) @system {
		prepareBars();
		manager.onProgress = (in QueuedRequest request, in QueueDetails queueDetails, in QueueItemProgress progress) @safe {
			import std.conv : text;
			import std.algorithm.comparison : among;
			if (progress.state == QueueItemState.starting) {
				progressTracker.setItemActive(queueDetails.ID);
			}
			progressTracker.setItemMaximum(queueDetails.ID, progress.size);
			progressTracker.setItemProgress(queueDetails.ID, progress.downloaded);
			if (progress.state == QueueItemState.error) {
				progressTracker.setItemStatus(queueDetails.ID, text(progress.state, " - ", progress.error.msg));
				progressTracker.completeItem(queueDetails.ID);
			} else {
				progressTracker.setItemStatus(queueDetails.ID, progress.state.text);
			}
			if (progress.state.among(QueueItemState.complete, QueueItemState.skipping)) {
				progressTracker.completeItem(queueDetails.ID);
			}
			progressTracker.updateDisplay();
		};
		manager.download(throwOnError);
		progressTracker.clear();
		loaded = false;
	}
	auto ref queueCount() @safe {
		return manager.queueCount;
	}
	auto ref preDownloadFunction() @safe {
		return manager.preDownloadFunction;
	}
	auto ref postDownloadFunction() @safe {
		return manager.postDownloadFunction;
	}
	auto ref onError() @safe {
		return manager.onError;
	}
	static PrettyDownloadCache systemCache() @safe {
		return PrettyDownloadCache(DownloadCache.systemCache);
	}
	private void prepareBars() @safe pure {
		import std.conv : text;
		if (!loaded) {
			foreach (id, request; manager.queue) {
				progressTracker.addNewItem(id);
				progressTracker.setItemName(id, request.label ? request.label : request.request.url.text);
			}
			loaded = true;
		}
	}
}
