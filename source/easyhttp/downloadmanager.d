module easyhttp.downloadmanager;

import easyhttp.http;
import easyhttp.url;
import easyhttp.util;
import std.stdio;

import core.thread;
import std.algorithm.comparison;
import std.concurrency;
import std.datetime;
import std.exception;
import std.file;
import std.functional;
import std.logger;
import std.path;
import std.range;
import std.random;
import std.typecons;
import std.variant;

enum ShouldContinue {
	no = 0,
	yes = 1,
	error = 2,
	retry = 3,
}

struct QueuedRequest {
	Request request;
	string destPath;
	bool autoCreateDirs;
	size_t retries = 1;
	FileExistsAction fileExistsAction;
	string label;
	bool skipDownload;
	ulong userData;
	Nullable!RequestDelay delay;
	void delegate(in QueuedRequest request, in QueueResult result, in QueueDetails qd) @safe postDownload;
	void delegate(in QueuedRequest request, in QueueResult result, in QueueDetails qd) @safe postDownloadSkip;
	ShouldContinue delegate(in QueuedRequest request, in QueueResult result, in QueueDetails qd) @safe postDownloadCheck;
	void delegate(in QueuedRequest request, in QueueDetails qd, in QueueError error) @safe nothrow onError;
	ShouldContinue delegate(in QueuedRequest request, in QueueDetails qd) @safe preDownload;
	void delegate(in QueuedRequest request, in QueueDetails qd, in QueueItemProgress progress) @safe onProgress;
	string delegate(in string basePath, in string receivedFilename) @safe pure generateName;
	private bool opEquals(const QueuedRequest req2) const @safe pure nothrow @nogc {
		if (destPath != req2.destPath) {
			return false;
		}
		if (postDownload != req2.postDownload) {
			return false;
		}
		return true;
	}
}
struct QueueDetails {
	ulong id;
	ulong count;
}
struct QueueError {
	size_t id;
	string msg;
}
struct QueueItem {
	size_t id;
	Request request;
	string destPath;
	FileExistsAction fileExistsAction;
	size_t retries;
	bool autoCreateDirs;
	string delegate(in string basePath, in string receivedFilename) @safe pure generateName;
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

struct RequestDelayEntry {
	RequestDelay definition;
	string mask;
}
struct RequestDelayState {
	Nullable!RequestDelay definition;
	DelayState state;
}

struct RequestQueue {
	uint queueCount = 4;
	package const(QueuedRequest)[] queue;
	void delegate(in QueuedRequest request, in QueueResult result, in QueueDetails qd) @safe postDownloadFunction;
	void delegate(in QueuedRequest request, in QueueResult result, in QueueDetails qd) @safe postDownloadSkipFunction;
	ShouldContinue delegate(in QueuedRequest request, in QueueResult result, in QueueDetails qd) @safe postDownloadCheck;
	void delegate(in QueuedRequest request, in QueueDetails qd, in QueueError error) @safe nothrow onError;
	ShouldContinue delegate(in QueuedRequest request, in QueueDetails qd) @safe preDownloadFunction;
	void delegate(in QueuedRequest request, in QueueDetails qd, in QueueItemProgress progress) @safe onProgress;
	string delegate(in string basePath, in string receivedFilename) @safe pure generateName;
	private RequestDelayEntry[] urlDelays;
	private RequestDelayState[string] domainDelays;
	private DelayState globalDelay;
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
		import std.algorithm.iteration : map, uniq;
		import std.algorithm.sorting : sort;
		auto indices = iota(0, queue.length).array;
		indices.sort!((x,y) => queue[x].destPath < queue[y].destPath)();
		queue = indices.uniq!((x,y) => queue[x] == queue[y]).map!(x => queue[x]).array;
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
	/++
		Add rate limiting for all hostnames matching the given string
	+/
	void rateLimitDomain(string hostnames, RequestDelay delay) @safe {
		urlDelays ~= RequestDelayEntry(delay, hostnames);
	}
	///
	package void handleDelay(const Nullable!RequestDelay qd, const URL url, size_t queueID = size_t.max) @safe {
		Duration delay;
		if (!qd.isNull) {
			delay = globalDelay.tryDelay(qd.get, Clock.currTime, rndGen);
		}
		ref entry = domainDelays.require(url.hostname, {
			RequestDelayState result;
			foreach (entry; urlDelays) {
				if (matchHostname(entry.mask, url.hostname)) {
					result.definition = entry.definition;
					break;
				}
			}
			return result;
		}());
		if (!entry.definition.isNull) {
			delay = max(delay, entry.state.tryDelay(entry.definition.get, Clock.currTime, rndGen));
		}
		static void trustedSleep(Duration duration) @trusted {
			Thread.sleep(duration);
		}
		if (delay > 0.seconds) {
			if (queueID != queueID.max) {
				updateProgress(queueID, QueueItemProgress(QueueItemState.waiting));
			}
			trustedSleep(delay);
		}
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
		ulong[] retryQueueIDs;
		while (completed < queueCount) {
			receive(
				(bool isReady, Tid child) {
					if (retryQueueIDs.length > 0) {
						const id = retryQueueIDs[0];
						retryQueueIDs = retryQueueIDs[1 .. $];
						// skip checks, they were done on the first try
						handleDelay(queue[id].delay, queue[id].request.url, id);
						updateProgress(id, QueueItemProgress(QueueItemState.starting));
						send(child, immutable QueueItem(id, queue[id].request.finalized, queue[id].destPath, queue[id].fileExistsAction, queue[id].retries, queue[id].autoCreateDirs, queue[id].generateName ? queue[id].generateName : generateName));
						return;
					}
					while (id < queue.length) {
						try {
							if (preDownload(id) == ShouldContinue.yes) {
								if (queue[id].skipDownload) {
									updateProgress(id, QueueItemProgress(QueueItemState.starting));
									QueueResult qResult;
									qResult.path = queue[id].destPath;
									postDownload(id, qResult);
									updateProgress(id, QueueItemProgress(QueueItemState.complete, 0, 0));
								} else {
									updateProgress(id, QueueItemProgress(QueueItemState.starting));
									assert(!save || (queue[id].destPath != ""));
									send(child, immutable QueueItem(id, queue[id].request.finalized, queue[id].destPath, queue[id].fileExistsAction, queue[id].retries, queue[id].autoCreateDirs, queue[id].generateName ? queue[id].generateName : generateName));
									id++;
									return;
								}
							} else {
								updateProgress(id, QueueItemProgress(QueueItemState.skipping));
							}
						} catch (Exception e) {
							auto progress = QueueItemProgress(QueueItemState.error);
							progress.error = QueueError(id, e.msg);
							errorOccurred(progress.error);
							updateProgress(id, progress);
						}
						id++;
					}
					completed++;
					send(child, true);
				},
				(immutable size_t successID, immutable QueueResult result, Tid child) nothrow {
					try {
						const shouldContinue = postDownload(successID, result);
						if (shouldContinue == ShouldContinue.yes) {
							updateProgress(successID, QueueItemProgress(QueueItemState.complete, result.response.content!(immutable(ubyte)[]).length, result.response.content!(immutable(ubyte)[]).length));
						} else if (shouldContinue == ShouldContinue.retry) {
							retryQueueIDs ~= successID;
							updateProgress(successID, QueueItemProgress(QueueItemState.error));
						} else if (shouldContinue == ShouldContinue.no) {
							updateProgress(successID, QueueItemProgress(QueueItemState.complete));
						}
					} catch (Exception e) {
						auto progress = QueueItemProgress(QueueItemState.error);
						progress.error = QueueError(successID, e.msg);
						errorOccurred(progress.error);
						updateProgress(successID, progress);
						if (save && result.path.exists) {
							try {
								remove(result.path);
							} catch (Exception) {} // we tried
						}
					}
				},
				(immutable size_t id, immutable QueueItemProgress progress) nothrow {
					updateProgress(id, progress);
				},
				(QueueError error) nothrow {
					errorOccurred(error);
					auto progress = QueueItemProgress(QueueItemState.error);
					progress.error = error;
					updateProgress(error.id, progress);
				}
			);
		}
		queue = [];
	}
	private void updateProgress(in ulong id, in QueueItemProgress progress) const @safe nothrow {
		try {
			if (onProgress) {
				onProgress(queue[id], QueueDetails(id, queue.length), progress);
			}
			if (queue[id].onProgress) {
				queue[id].onProgress(queue[id], QueueDetails(id, queue.length), progress);
			}
		} catch (Exception e) {
			errorOccurred(QueueError(id, e.msg));
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
		} else if (result == ShouldContinue.no) {
			if (postDownloadSkipFunction) {
				postDownloadSkipFunction(queue[id], queueResult, QueueDetails(id, queue.length));
			}
			if (queue[id].postDownloadSkip) {
				queue[id].postDownloadSkip(queue[id], queueResult, QueueDetails(id, queue.length));
			}
		}
		enforce(result != ShouldContinue.error, "Post-download check indicated failure");
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
		enforce(result != ShouldContinue.error, "Pre-download check indicated failure");
		return result;
	}
	private void errorOccurred(in QueueError error) const @safe nothrow {
		if (onError) {
			onError(queue[error.id], QueueDetails(error.id, queue.length), error);
		}
		if (queue[error.id].onError) {
			queue[error.id].onError(queue[error.id], QueueDetails(error.id, queue.length), error);
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
				size_t lastProgress;
				void updateProgress(size_t amount, size_t total) {
					if (amount == lastProgress) {
						return;
					}
					send(ownerTid, download.id, immutable QueueItemProgress(QueueItemState.downloading, amount, total));
					lastProgress = amount;
				}
				if (download.autoCreateDirs) {
					mkdirRecurse(download.destPath.dirName);
				}
				do {
					attemptsLeft--;
					try {
						if (save) {
							immutable response = download.request.saveTo(download.destPath, download.fileExistsAction, throwOnError, &updateProgress, download.generateName);
							send(ownerTid, download.id, immutable QueueResult(response.response, response.path, response.overwritten, download.retries - attemptsLeft), thisTid);
						} else {
							immutable response = download.request.perform(&updateProgress);
							enforce(!throwOnError || response.statusCode.isSuccessful, new StatusException(response.statusCode, download.request.url));
							send(ownerTid, download.id, immutable QueueResult(response, "", false, download.retries - attemptsLeft), thisTid);
						}
						break;
					} catch (Exception e) {
						debug(verbosehttp) tracef("Error downloading: %s", e);
						if (attemptsLeft == 0) {
							send(ownerTid, QueueError(download.id, e.msg));
						}
					} catch (Throwable e) {
						debug(verbosehttp) tracef("Error downloading: %s", e);
						if (attemptsLeft == 0) {
							send(ownerTid, QueueError(download.id, e.msg));
							tracef("Error: %s", e);
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
	// retry once
	with(RequestQueue()) {
		uint[20] tries;
		bool[20] successes;
		postDownloadCheck = (r, r2, q) {
			if (tries[q.id]++ > 0) {
				return ShouldContinue.yes;
			}
			return ShouldContinue.retry;
		};
		auto dlReq = QueuedRequest();
		dlReq.request = getRequest(URL("https://misc.herringway.pw/whack.gif"));
		dlReq.postDownload = (r, r2, q) {
			successes[q.id] = true;
			remove(r.destPath);
		};
		foreach (i; 0 .. 20) {
			dlReq.destPath = format!"whack%d.gif"(i);
			add(dlReq);
		}
		version(online) {
			download();
			foreach (success; successes) {
				assert(success);
			}
		}
	}
}

private bool matchHostname(string wildcard, string hostname) @safe pure {
	return globMatch(hostname, wildcard);
}

@safe pure unittest {
	assert(matchHostname("*", ""));
	assert(matchHostname("*", "example.com"));
	assert(!matchHostname("example.net", "example.com"));
	assert(!matchHostname("*.example.com", "example.com"));
	assert(matchHostname("*.example.com", "subdomain.example.com"));
	assert(!matchHostname("*.example.net", "subdomain.example.com"));
}
