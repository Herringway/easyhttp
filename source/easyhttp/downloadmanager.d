module easyhttp.downloadmanager;

import easyhttp.http;
import std.stdio;

import std.concurrency;
import std.experimental.logger;
import std.functional;
import std.path;
import std.range;
import std.variant;

enum ShouldDownload {
	no = 0,
	yes = 1,
}

struct DownloadRequest {
	Request request;
	string destPath;
	size_t retries = 1;
	FileExistsAction fileExistsAction;
	void delegate(in DownloadRequest request, in DownloadResult result, in QueueDetails qd) @safe postDownload;
	ShouldDownload delegate(in DownloadRequest request, in QueueDetails qd) @safe preDownload;
	void delegate(in DownloadRequest request, in QueueDetails qd, in DownloadError error) @safe onError;
	void delegate(in DownloadRequest request, in QueueDetails qd, in DownloadProgress progress) @safe onProgress;
}
struct QueueDetails {
	ulong ID;
	ulong count;
}
struct DownloadError {
	size_t ID;
	string msg;
}
struct QueuedDownload {
	size_t ID;
	Request request;
	string destPath;
	FileExistsAction fileExistsAction;
	size_t retries;
}

struct DownloadResult {
	SavedFileInformation response;
	size_t successfulAttempt;
	DownloadError error;
}

enum DownloadState {
	waiting,
	downloading,
	skipping,
	starting,
	complete,
	error
}

struct DownloadProgress {
	DownloadState state;
	size_t downloaded;
	DownloadError error;
	void toString(T)(T sink) const if (isOutputRange!(T, char[])) {
		final switch (state) {
			case DownloadState.waiting:
				put(sink, "Waiting");
				break;
			case DownloadState.downloading:
				put(sink, "Downloading");
				break;
			case DownloadState.skipping:
				put(sink, "Skipping");
				break;
			case DownloadState.starting:
				put(sink, "Starting");
				break;
			case DownloadState.complete:
				put(sink, "Complete");
				break;
			case DownloadState.error:
				put(sink, "Error - ");
				put(sink, error.msg);
				break;
		}
	}
}

struct DownloadManager {
	uint queueCount = 4;
	private const(DownloadRequest)[] queue;
	void delegate(in DownloadRequest request, in DownloadResult result, in QueueDetails qd) @safe postDownloadFunction;
	void delegate(in DownloadRequest request, in QueueDetails qd, in DownloadError error) @safe onError;
	ShouldDownload delegate(in DownloadRequest request, in QueueDetails qd) @safe preDownloadFunction;
	void delegate(in DownloadRequest request, in QueueDetails qd, in DownloadProgress progress) @safe onProgress;
	bool pathAlreadyInQueue(const string path) nothrow @safe {
		import std.algorithm.iteration : map;
		import std.algorithm.searching : canFind;
		return queue.map!(x => x.destPath).canFind(path);
	}
	void add(const DownloadRequest request) nothrow @safe
		in(request.destPath.isValidPath, "Invalid path: "~request.destPath)
	{
		queue ~= request;
	}
	void prepare() @safe pure {
		import std.algorithm.iteration : uniq;
		import std.algorithm.sorting : sort;
		auto indices = iota(0, queue.length).array;
		indices.sort!((x, y) => queue[x].request.url > queue[y].request.url)();
		queue = indexed(queue, indices).uniq().array;
	}
	void execute() @system {
		import std.range : empty, front, popFront;
		auto downloaders = new Tid[](queueCount);
		foreach (idx, ref downloader; downloaders) {
			downloader = spawn(&downloadRoutine);
			debug import std.format : format;
			debug register(format!"downloader %s"(idx), downloader);
		}
		ulong completed;
		ulong id;
		while (completed < queueCount) {
			receive(
				(bool isReady, Tid child) {
					while (id < queue.length) {
						if (preDownload(id) == ShouldDownload.yes) {
							updateProgress(id, DownloadProgress(DownloadState.starting));
							send(child, immutable QueuedDownload(id, queue[id].request.finalized, queue[id].destPath, queue[id].fileExistsAction, queue[id].retries));
							id++;
							return;
						} else {
							updateProgress(id, DownloadProgress(DownloadState.skipping));
						}
						id++;
					}
					completed++;
					send(child, true);
				},
				(immutable size_t successID, immutable DownloadResult result) {
					postDownload(successID, result);
					updateProgress(successID, DownloadProgress(DownloadState.complete));
				},
				(DownloadError error) {
					errorOccurred(error.ID, error);
					auto progress = DownloadProgress(DownloadState.error);
					progress.error = error;
					updateProgress(error.ID, progress);
				}
			);
		}
	}
	private void updateProgress(in ulong id, in DownloadProgress progress) const @safe {
		if (onProgress) {
			onProgress(queue[id], QueueDetails(id, queue.length), progress);
		}
		if (queue[id].onProgress) {
			queue[id].onProgress(queue[id], QueueDetails(id, queue.length), progress);
		}
	}
	private void postDownload(in ulong id, in DownloadResult result) const @safe {
		if (postDownloadFunction) {
			postDownloadFunction(queue[id], result, QueueDetails(id, queue.length));
		}
		if (queue[id].postDownload) {
			queue[id].postDownload(queue[id], result, QueueDetails(id, queue.length));
		}
	}
	private ShouldDownload preDownload(in ulong id) const @safe {
		ShouldDownload result;
		if (preDownloadFunction) {
			result = preDownloadFunction(queue[id], QueueDetails(id, queue.length));
		}
		if ((result == ShouldDownload.yes) && queue[id].preDownload) {
			result = queue[id].preDownload(queue[id], QueueDetails(id, queue.length));
		}
		return result;
	}
	private void errorOccurred(in ulong id, in DownloadError error) const @safe {
		if (onError) {
			onError(queue[id], QueueDetails(id, queue.length), error);
		}
		if (queue[id].onError) {
			queue[id].onError(queue[id], QueueDetails(id, queue.length), error);
		}
	}
}
private void downloadRoutine() @system {
	bool finished;
	while (!finished) {
		send(ownerTid, true, thisTid);
		receive(
			(bool done) {
				finished = true;
			},
			(immutable QueuedDownload download) {
				import std.algorithm.comparison : max;
				size_t attemptsLeft = max(1, download.retries);
				do {
					attemptsLeft--;
					try {
						immutable response = download.request.saveTo(download.destPath, download.fileExistsAction);
						send(ownerTid, download.ID, immutable DownloadResult(response, download.retries - attemptsLeft));
						break;
					} catch (Exception e) {
						if (attemptsLeft == 0) {
							send(ownerTid, DownloadError(download.ID, e.msg));
						}
					} catch (Throwable e) {
						if (attemptsLeft == 0) {
							send(ownerTid, DownloadError(download.ID, e.msg));
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
	import easyhttp.simple : getRequest;
	import std.file : exists, remove;
	import std.format : format;
	with(DownloadManager()) {
		bool pre1, pre2, post1, post2;
		preDownloadFunction = (r, q) {
			pre1 = true;
			return ShouldDownload.yes;
		};
		postDownloadFunction = (r, r2, q) {
			post1 = true;
		};
		auto dlReq = DownloadRequest();
		dlReq.request = getRequest(URL("https://misc.herringway.pw/whack.gif"));
		dlReq.destPath = "whack.gif";
		dlReq.preDownload = (r, q) {
			pre2 = true;
			return ShouldDownload.yes;
		};
		dlReq.postDownload = (r, r2, q) {
			post2 = true;
			remove(r.destPath);
		};
		add(dlReq);
		version(online) {
			execute();
			assert(pre1 && pre2 && post1 && post2);
		}
	}
	with(DownloadManager()) {
		bool pre1, pre2, post1, post2;
		preDownloadFunction = (r, q) {
			pre1 = true;
			return ShouldDownload.yes;
		};
		postDownloadFunction = (r, r2, q) {
			post1 = true;
		};
		auto dlReq = DownloadRequest();
		dlReq.request = getRequest(URL("https://misc.herringway.pw/whack.gif"));
		dlReq.preDownload = (r, q) {
			pre2 = true;
			return ShouldDownload.yes;
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
			execute();
			assert(pre1 && pre2 && post1 && post2);
		}
	}
	// no downloads pass
	with(DownloadManager()) {
		bool pre1, pre2, post1, post2;
		preDownloadFunction = (r, q) {
			pre1 = true;
			return ShouldDownload.yes;
		};
		postDownloadFunction = (r, r2, q) {
			post1 = true;
		};
		onProgress = (req, qd, p) {
			writefln!"[%05d/%05d] Downloading %s to %s"(qd.ID, qd.count, req.request.url, req.destPath);
		};
		auto dlReq = DownloadRequest();
		dlReq.request = getRequest(URL("https://misc.herringway.pw/whack.gif"));
		dlReq.preDownload = (r, q) {
			pre2 = true;
			return ShouldDownload.no;
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
			execute();
			assert(pre1 && pre2 && !post1 && !post2);
		}
	}
	// no downloads pass (global)
	with(DownloadManager()) {
		bool pre1, pre2, post1, post2;
		preDownloadFunction = (r, q) {
			pre1 = true;
			return ShouldDownload.no;
		};
		postDownloadFunction = (r, r2, q) {
			post1 = true;
		};
		auto dlReq = DownloadRequest();
		dlReq.request = getRequest(URL("https://misc.herringway.pw/whack.gif"));
		dlReq.preDownload = (r, q) {
			pre2 = true;
			return ShouldDownload.yes;
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
			execute();
			assert(pre1 && !pre2 && !post1 && !post2);
		}
	}
}
