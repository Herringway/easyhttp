module easyhttp.downloadmanager;

import easyhttp.http;
import std.stdio;

import std.concurrency;
import std.experimental.logger;
import std.functional;
import std.path;
import std.range;
import std.variant;

enum ShouldContinue {
	no = 0,
	yes = 1,
	error = 2,
}

struct QueuedRequest {
	Request request;
	string destPath;
	size_t retries = 1;
	FileExistsAction fileExistsAction;
	string label;
	bool skipDownload;
	void delegate(in QueuedRequest request, in QueueResult result, in QueueDetails qd) @safe postDownload;
	ShouldContinue delegate(in QueuedRequest request, in QueueResult result, in QueueDetails qd) @safe postDownloadCheck;
	void delegate(in QueuedRequest request, in QueueDetails qd, in QueueError error) @safe onError;
	ShouldContinue delegate(in QueuedRequest request, in QueueDetails qd) @safe preDownload;
	void delegate(in QueuedRequest request, in QueueDetails qd, in QueueItemProgress progress) @safe onProgress;
}
struct QueueDetails {
	ulong ID;
	ulong count;
}
struct QueueError {
	size_t ID;
	string msg;
}
struct QueueItem {
	size_t ID;
	Request request;
	string destPath;
	FileExistsAction fileExistsAction;
	size_t retries;
}

struct QueueResult {
	Response response;
	string path;
	bool overwritten;
	size_t successfulAttempt;
	QueueError error;
}

enum QueueItemState {
	waiting,
	downloading,
	skipping,
	starting,
	complete,
	error
}

struct QueueItemProgress {
	QueueItemState state;
	size_t downloaded;
	size_t size;
	QueueError error;
	void toString(T)(T sink) const if (isOutputRange!(T, char[])) {
		final switch (state) {
			case QueueItemState.waiting:
				put(sink, "Waiting");
				break;
			case QueueItemState.downloading:
				put(sink, "Downloading");
				break;
			case QueueItemState.skipping:
				put(sink, "Skipping");
				break;
			case QueueItemState.starting:
				put(sink, "Starting");
				break;
			case QueueItemState.complete:
				put(sink, "Complete");
				break;
			case QueueItemState.error:
				put(sink, "Error - ");
				put(sink, error.msg);
				break;
		}
	}
}

struct RequestQueue {
	uint queueCount = 4;
	package const(QueuedRequest)[] queue;
	void delegate(in QueuedRequest request, in QueueResult result, in QueueDetails qd) @safe postDownloadFunction;
	ShouldContinue delegate(in QueuedRequest request, in QueueResult result, in QueueDetails qd) @safe postDownloadCheck;
	void delegate(in QueuedRequest request, in QueueDetails qd, in QueueError error) @safe onError;
	ShouldContinue delegate(in QueuedRequest request, in QueueDetails qd) @safe preDownloadFunction;
	void delegate(in QueuedRequest request, in QueueDetails qd, in QueueItemProgress progress) @safe onProgress;
	bool pathAlreadyInQueue(const string path) nothrow @safe {
		import std.algorithm.iteration : map;
		import std.algorithm.searching : canFind;
		return queue.map!(x => x.destPath).canFind(path);
	}
	size_t add(const QueuedRequest request) nothrow @safe
		in((request.destPath == "") || request.destPath.isValidPath, "Invalid path: '"~request.destPath~"'")
	{
		queue ~= request;
		return queue.length - 1;
	}
	/++
		Cleans up the download queue for more efficient downloading. Sorts queued items
		by URL, removes duplicates.
	+/
	void prepare() @safe pure {
		import std.algorithm.iteration : uniq;
		import std.algorithm.sorting : sort;
		auto indices = iota(0, queue.length).array;
		indices.sort!((x, y) => queue[x].request.url > queue[y].request.url)();
		queue = indexed(queue, indices).uniq().array;
	}
	/++
		Begin downloading queued items.
	+/
	void download(bool throwOnError = true) @system {
		process(true, throwOnError);
	}
	/++
		Begin executing queued requests.
	+/
	void perform(bool throwOnError = true) @system {
		process(false, throwOnError);
	}
	private void process(bool save, bool throwOnError) @system {
		import std.range : empty, front, popFront;
		auto downloaders = new Tid[](queueCount);
		foreach (idx, ref downloader; downloaders) {
			downloader = spawn(&downloadRoutine, save, throwOnError);
			debug import std.format : format;
			debug register(format!"downloader %s"(idx), downloader);
		}
		ulong completed;
		ulong id;
		while (completed < queueCount) {
			receive(
				(bool isReady, Tid child) {
					while (id < queue.length) {
						if (preDownload(id) == ShouldContinue.yes) {
							if (queue[id].skipDownload) {
								updateProgress(id, QueueItemProgress(QueueItemState.starting));
								postDownload(id, QueueResult.init);
								updateProgress(id, QueueItemProgress(QueueItemState.complete, 0, 0));
							} else {
								updateProgress(id, QueueItemProgress(QueueItemState.starting));
								assert(!save || (queue[id].destPath != ""));
								send(child, immutable QueueItem(id, queue[id].request.finalized, queue[id].destPath, queue[id].fileExistsAction, queue[id].retries));
								id++;
								return;
							}
						} else {
							updateProgress(id, QueueItemProgress(QueueItemState.skipping));
						}
						id++;
					}
					completed++;
					send(child, true);
				},
				(immutable size_t successID, immutable QueueResult result) {
					if (postDownload(successID, result) == ShouldContinue.yes) {
						updateProgress(successID, QueueItemProgress(QueueItemState.complete, result.response.content!(immutable(ubyte)[]).length, result.response.content!(immutable(ubyte)[]).length));
					} else {
						updateProgress(successID, QueueItemProgress(QueueItemState.error));
					}
				},
				(immutable size_t id, immutable QueueItemProgress progress) {
					updateProgress(id, progress);
				},
				(QueueError error) {
					errorOccurred(error.ID, error);
					auto progress = QueueItemProgress(QueueItemState.error);
					progress.error = error;
					updateProgress(error.ID, progress);
				}
			);
		}
		queue = [];
	}
	private void updateProgress(in ulong id, in QueueItemProgress progress) const @safe {
		if (onProgress) {
			onProgress(queue[id], QueueDetails(id, queue.length), progress);
		}
		if (queue[id].onProgress) {
			queue[id].onProgress(queue[id], QueueDetails(id, queue.length), progress);
		}
	}
	private ShouldContinue postDownload(in ulong id, in QueueResult queueResult) const @safe {
		ShouldContinue result = ShouldContinue.yes;
		if (postDownloadCheck) {
			result = postDownloadCheck(queue[id], queueResult, QueueDetails(id, queue.length));
		}
		if (result == ShouldContinue.yes) {
			if(queue[id].postDownloadCheck) {
				result = queue[id].postDownloadCheck(queue[id], queueResult, QueueDetails(id, queue.length));
			}
			if (result == ShouldContinue.yes) {
				if (postDownloadFunction) {
					postDownloadFunction(queue[id], queueResult, QueueDetails(id, queue.length));
				}
				if (queue[id].postDownload) {
					queue[id].postDownload(queue[id], queueResult, QueueDetails(id, queue.length));
				}
			}
		}
		return result;
	}
	private ShouldContinue preDownload(in ulong id) const @safe {
		ShouldContinue result = ShouldContinue.yes;
		if (preDownloadFunction) {
			result = preDownloadFunction(queue[id], QueueDetails(id, queue.length));
		}
		if ((result == ShouldContinue.yes) && queue[id].preDownload) {
			result = queue[id].preDownload(queue[id], QueueDetails(id, queue.length));
		}
		return result;
	}
	private void errorOccurred(in ulong id, in QueueError error) const @safe {
		if (onError) {
			onError(queue[id], QueueDetails(id, queue.length), error);
		}
		if (queue[id].onError) {
			queue[id].onError(queue[id], QueueDetails(id, queue.length), error);
		}
	}
}
private void downloadRoutine(bool save, bool throwOnError) @system {
	bool finished;
	while (!finished) {
		send(ownerTid, true, thisTid);
		receive(
			(bool done) {
				finished = true;
			},
			(immutable QueueItem download) {
				import std.algorithm.comparison : max;
				import std.exception : enforce;
				size_t attemptsLeft = max(1, download.retries);
				void updateProgress(size_t amount, size_t total) {
					send(ownerTid, download.ID, immutable QueueItemProgress(QueueItemState.downloading, amount, total));
				}
				do {
					attemptsLeft--;
					try {
						if (save) {
							immutable response = download.request.saveTo(download.destPath, download.fileExistsAction, throwOnError, &updateProgress);
							send(ownerTid, download.ID, immutable QueueResult(response.response, response.path, response.overwritten, download.retries - attemptsLeft));
						} else {
							immutable response = download.request.perform(&updateProgress);
							enforce(!throwOnError || response.statusCode.isSuccessful, new StatusException(response.statusCode, download.request.url));
							send(ownerTid, download.ID, immutable QueueResult(response, "", false, download.retries - attemptsLeft));
						}
						break;
					} catch (Exception e) {
						if (attemptsLeft == 0) {
							send(ownerTid, QueueError(download.ID, e.msg));
						}
					} catch (Throwable e) {
						if (attemptsLeft == 0) {
							send(ownerTid, QueueError(download.ID, e.msg));
						}
					}
				} while(attemptsLeft > 0);
			},
			(Variant v) {
				tracef("Got unknown message %s - %s", v.type, v);
			}
		);
	}
}
@system unittest {
	import easyhttp.url : URL;
	import easyhttp.simple : getRequest, postRequest;
	import std.file : exists, remove;
	import std.format : format;
	with(RequestQueue()) {
		bool pre1, pre2, post1, post2;
		preDownloadFunction = (r, q) {
			pre1 = true;
			return ShouldContinue.yes;
		};
		postDownloadFunction = (r, r2, q) {
			post1 = true;
		};
		auto dlReq = QueuedRequest();
		dlReq.request = getRequest(URL("https://misc.herringway.pw/whack.gif"));
		dlReq.destPath = "whack.gif";
		dlReq.preDownload = (r, q) {
			pre2 = true;
			return ShouldContinue.yes;
		};
		dlReq.postDownload = (r, r2, q) {
			post2 = true;
			remove(r.destPath);
		};
		add(dlReq);
		version(online) {
			download();
			assert(pre1 && pre2 && post1 && post2);
		}
	}
	with(RequestQueue()) {
		bool pre1, pre2, post1, post2;
		preDownloadFunction = (r, q) {
			pre1 = true;
			return ShouldContinue.yes;
		};
		postDownloadFunction = (r, r2, q) {
			post1 = true;
		};
		auto dlReq = QueuedRequest();
		dlReq.request = postRequest(URL("http://misc.herringway.pw/.test/"), "hi");
		dlReq.postDownload = (r, r2, q) {
			assert(r2.response.content == "hi");
		};
		add(dlReq);
		version(online) {
			perform();
			assert(pre1 && post1);
		}
	}
	with(RequestQueue()) {
		bool pre1, pre2, post1, post2;
		preDownloadFunction = (r, q) {
			pre1 = true;
			return ShouldContinue.yes;
		};
		postDownloadFunction = (r, r2, q) {
			post1 = true;
		};
		auto dlReq = QueuedRequest();
		dlReq.request = getRequest(URL("https://misc.herringway.pw/whack.gif"));
		dlReq.preDownload = (r, q) {
			pre2 = true;
			return ShouldContinue.yes;
		};
		dlReq.postDownload = (r, r2, q) {
			post2 = true;
			remove(r.destPath);
		};
		foreach (i; 0 .. 20) {
			dlReq.destPath = format!"whack%d.gif"(i);
			add(dlReq);
		}
		version(online) {
			download();
			assert(pre1 && pre2 && post1 && post2);
		}
	}
	// no downloads pass
	with(RequestQueue()) {
		bool pre1, pre2, post1, post2;
		preDownloadFunction = (r, q) {
			pre1 = true;
			return ShouldContinue.yes;
		};
		postDownloadFunction = (r, r2, q) {
			post1 = true;
		};
		onProgress = (req, qd, p) {
			assert(p.state == QueueItemState.skipping);
		};
		auto dlReq = QueuedRequest();
		dlReq.request = getRequest(URL("https://misc.herringway.pw/whack.gif"));
		dlReq.preDownload = (r, q) {
			pre2 = true;
			return ShouldContinue.no;
		};
		dlReq.postDownload = (r, r2, q) {
			post2 = true;
			remove(r.destPath);
		};
		foreach (i; 0 .. 20) {
			dlReq.destPath = format!"whack%d.gif"(i);
			add(dlReq);
		}
		version(online) {
			download();
			assert(pre1 && pre2 && !post1 && !post2);
		}
	}
	// no downloads pass (global)
	with(RequestQueue()) {
		bool pre1, pre2, post1, post2;
		preDownloadFunction = (r, q) {
			pre1 = true;
			return ShouldContinue.no;
		};
		postDownloadFunction = (r, r2, q) {
			post1 = true;
		};
		auto dlReq = QueuedRequest();
		dlReq.request = getRequest(URL("https://misc.herringway.pw/whack.gif"));
		dlReq.preDownload = (r, q) {
			pre2 = true;
			return ShouldContinue.yes;
		};
		dlReq.postDownload = (r, r2, q) {
			post2 = true;
			remove(r.destPath);
		};
		foreach (i; 0 .. 20) {
			dlReq.destPath = format!"whack%d.gif"(i);
			add(dlReq);
		}
		version(online) {
			download();
			assert(pre1 && !pre2 && !post1 && !post2);
		}
	}
}
