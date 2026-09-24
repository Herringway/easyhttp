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
	private ProgressTracker progressTracker;
	private bool loaded;
	bool noColours;

	void showTotal() nothrow @safe pure {
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
		manager.onProgress = (request, queueDetails, progress) @safe {
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
	auto ref preDownloadFunction() => manager.preDownloadFunction;
	auto ref postDownloadFunction() => manager.postDownloadFunction;
	auto ref postDownloadSkipFunction() => manager.postDownloadSkipFunction;
	auto ref postDownloadCheck() => manager.postDownloadCheck;
	auto ref onError() => manager.onError;
	auto ref minimumUpdateWait() => progressTracker.minimumUpdateWait;
	auto ref generateName() => manager.generateName;
	auto ref queueCount() => manager.queueCount;
	auto rateLimitDomain(string domains, RequestDelay delay) => manager.rateLimitDomain(domains, delay);
	static PrettyDownloadManager systemCache() @safe => PrettyDownloadManager(RequestQueue.systemCache);
	private void prepareBars() @safe pure {
		if (!loaded) {
			foreach (id, request; manager.queue) {
				progressTracker.addNewItem(id);
				progressTracker.setItemName(id, request.label ? request.label : request.request.url.text);
				progressTracker.setItemUnits(id, ProgressUnit.bytes);
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
	with(PrettyDownloadManager()) {
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
