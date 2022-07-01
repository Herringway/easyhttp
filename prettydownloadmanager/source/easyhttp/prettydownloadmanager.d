module easyhttp.prettydownloadmanager;

import progresso.progresstracker;
import easyhttp.downloadmanager;

import std.experimental.logger;

struct PrettyDownloadManager {
	private RequestQueue manager;
	private ProgressTracker progressTracker;

	void showTotal() nothrow @safe pure {
		progressTracker.showTotal = true;
		progressTracker.totalItemsOnly = true;
	}
	bool pathAlreadyInQueue(const string path) nothrow @safe {
		return manager.pathAlreadyInQueue(path);
	}
	void add(const QueuedRequest request) @safe {
		import std.conv : text;
		const id = manager.add(request);
		progressTracker.addNewItem(id);
		progressTracker.setItemName(id, request.request.url.text);
	}
	void prepare() @safe pure {
		manager.prepare();
	}
	void download() @system {
		manager.onProgress = (request, queueDetails, progress) @safe {
			import std.conv : text;
			if (progress.state == QueueItemState.starting) {
				//warningf("Starting %s", queueDetails.ID);
				progressTracker.setItemActive(queueDetails.ID);
			}
			//warningf("Setting details for %s: %s, %s, %s", queueDetails.ID, progress.size, progress.downloaded, progress.state);
			progressTracker.setItemMaximum(queueDetails.ID, progress.size);
			progressTracker.setItemProgress(queueDetails.ID, progress.downloaded);
			progressTracker.setItemStatus(queueDetails.ID, progress.state.text);
			if (progress.state == QueueItemState.complete) {
				//warningf("Completed %s", queueDetails.ID);
				progressTracker.completeItem(queueDetails.ID);
			}
			progressTracker.updateDisplay();
			//writeln(progress);
		};
		manager.download();
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
