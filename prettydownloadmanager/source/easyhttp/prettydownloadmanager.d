module easyhttp.prettydownloadmanager;

import progresso;
import easyhttp.downloadmanager;
import easyhttp.http;
import easyhttp.util;

import std.algorithm.comparison;
import std.conv;
import std.logger;

struct PrettyDownloadManager {
	private RequestQueue manager;
	private ProgressTracker* progressTracker;
	private ProgressItem* progressRoot;
	private bool loaded;
	bool noColours;

	this(ProgressTracker* tracker) @safe pure {
		progressTracker = tracker;
		progressRoot = &progressTracker.root;
	}
	this(ProgressTracker* tracker, ProgressItem* root) @safe pure {
		progressTracker = tracker;
		progressRoot = root;
	}
	void showTotal() nothrow @safe pure {
		assert(progressTracker);
		progressTracker.showTotal = true;
		progressTracker.totalItemsOnly = true;
	}
	bool pathAlreadyInQueue(const string path) nothrow @safe => manager.pathAlreadyInQueue(path);
	auto add(QueuedRequest request) @safe => manager.add(request);
	void prepare() @safe pure {
		manager.prepare();
		prepareBars();
	}
	void download(bool throwOnError = true) @system {
		prepareBars();
		progressRoot.setActive();
		manager.onProgress = (request, queueDetails, progress) @safe {
			ref progressItem = progressRoot.matching(queueDetails.id);
			if (progress.state == QueueItemState.starting) {
				progressItem.state = ProgressItemState.active;
			}
			progressItem.maximum = progress.size;
			progressItem.current = progress.downloaded;
			progressItem.status = progress.text;
			if (progress.state == QueueItemState.error) {
				if (!noColours) {
					progressItem.from = RGB(255, 0, 0);
					progressItem.colourMode = ColourMode.unchanging;
				}
			}
			if (progress.state.among(QueueItemState.complete, QueueItemState.error)) {
				progressItem.state = ProgressItemState.complete;
			}
			progressTracker.updateDisplay();
		};
		manager.download(throwOnError);
		progressTracker.updateDisplay();
		loaded = false;
	}
	auto ref preDownloadFunction() => manager.preDownloadFunction;
	auto ref postDownloadFunction() => manager.postDownloadFunction;
	auto ref postDownloadSkipFunction() => manager.postDownloadSkipFunction;
	auto ref postDownloadCheck() => manager.postDownloadCheck;
	auto ref onError() => manager.onError;
	auto ref minimumUpdateWait() => progressTracker.minimumUpdateWait;
	auto ref generateName() => manager.generateName;
	auto ref queueCount() => manager.queueCount;
	auto rateLimitDomain(string domains, RequestDelay delay) => manager.rateLimitDomain(domains, delay);
	static PrettyDownloadManager systemCache(ProgressTracker* tracker) @safe {
		auto result = PrettyDownloadManager(tracker);
		result.manager = RequestQueue.systemCache;
		return result;
	}
	static PrettyDownloadManager systemCache(ProgressTracker* tracker, ProgressItem* root) @safe {
		auto result = PrettyDownloadManager(tracker, root);
		result.manager = RequestQueue.systemCache;
		return result;
	}
	private void prepareBars() @safe pure {
		assert(progressTracker && progressRoot);
		if (!loaded) {
			foreach (id, request; manager.queue) {
				progressRoot.addNewItem(ProgressItem(
					name: request.label ? request.label : request.request.url.text,
					unit: ProgressUnit.bytes,
					id: id,
					from: RGB(0, 255, 0),
					colourMode: noColours ? ColourMode.none : ColourMode.unchanging,
				));
			}
			loaded = true;
		}
	}
}

@system unittest {
	import easyhttp.url : URL;
	import easyhttp.simple : getRequest;
	import std.file : exists, remove;
	with(PrettyDownloadManager(new ProgressTracker)) {
		showTotal();
		foreach (i; 0 .. 100) {
			auto dlReq = QueuedRequest();
			dlReq.request = getRequest(URL("https://misc.herringway.pw/whack.gif"));
			dlReq.destPath = text("whack", i, ".gif");
			dlReq.postDownload = (r, r2, q) {
				if (r.destPath.exists) remove(r.destPath);
			};
			add(dlReq);
		}
		//version(online) {
			download();
		//}
	}
}
