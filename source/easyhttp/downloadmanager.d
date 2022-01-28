module easyhttp.downloadmanager;

import easyhttp.http;
import std.stdio;

import std.concurrency;
import std.functional;
import std.path;
import std.variant;
import std.experimental.logger;

enum ShouldDownload {
	no = 0,
	yes = 1,
}

struct DownloadRequest {
	Request request;
	string destPath;
	void delegate(const DownloadRequest request, const DownloadResult result, const QueueDetails qd) postDownload;
	ShouldDownload delegate(const DownloadRequest request, const QueueDetails qd) preDownload;
	void delegate(const DownloadRequest request, const QueueDetails qd, const DownloadError error) onError;
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
	bool overwrite;
}

struct DownloadResult {
	SavedFileInformation response;
}

struct DownloadManager {
	uint queueCount = 4;
	private const(DownloadRequest)[] queue;
	void delegate(const DownloadRequest request, const DownloadResult result, const QueueDetails qd) postDownloadFunction;
	void delegate(const DownloadRequest request, const QueueDetails qd, const DownloadError error) onError;
	ShouldDownload delegate(const DownloadRequest request, const QueueDetails qd) preDownloadFunction;
	bool pathAlreadyInQueue(const string path) nothrow {
		import std.algorithm.iteration : map;
		import std.algorithm.searching : canFind;
		return queue.map!(x => x.destPath).canFind(path);
	}
	void add(const DownloadRequest request) nothrow
		in(request.destPath.isValidPath, "Invalid path: "~request.destPath)
	{
		queue ~= request;
	}
	void execute() {
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
						bool shouldContinue = true;
						if (preDownloadFunction) {
							shouldContinue = preDownloadFunction(queue[id], QueueDetails(id, queue.length)) == ShouldDownload.yes;
						}
						if (shouldContinue && queue[id].preDownload) {
							shouldContinue = queue[id].preDownload(queue[id], QueueDetails(id, queue.length)) == ShouldDownload.yes;
						}
						if (shouldContinue) {
							send(child, immutable QueuedDownload(id, queue[id].request.finalized, queue[id].destPath));
							id++;
							return;
						}
						id++;
					}
					completed++;
					send(child, true);
				},
				(immutable size_t successID, immutable DownloadResult result) {
					if (postDownloadFunction) {
						postDownloadFunction(queue[successID], result, QueueDetails(successID, queue.length));
					}
					if (queue[successID].postDownload) {
						queue[successID].postDownload(queue[successID], result, QueueDetails(successID, queue.length));
					}
				},
				(DownloadError error) {
					if (queue[error.ID].onError) {
						queue[error.ID].onError(queue[error.ID], QueueDetails(error.ID, queue.length), error);
					}
					if (onError) {
						onError(queue[error.ID], QueueDetails(error.ID, queue.length), error);
					}
				}
			);
		}
	}
}
void downloadRoutine() {
	bool finished;
	while (!finished) {
		send(ownerTid, true, thisTid);
		receive(
			(bool done) {
				finished = true;
			},
			(immutable QueuedDownload download) {
				try {
					immutable response = download.request.saveTo(download.destPath, download.overwrite);
					send(ownerTid, download.ID, immutable DownloadResult(response));
				} catch (Exception e) {
					send(ownerTid, DownloadError(download.ID, e.msg));
				} catch (Throwable e) {
					send(ownerTid, DownloadError(download.ID, e.msg));
				}
			},
			(Variant v) {
				tracef("Got unknown message %s - %s", v.type, v);
			}
		);
	}
}
class DownloadException : Exception {
	public this(string message, string file = __FILE__, size_t line = __LINE__) {
		super(message, file, line);
	}
}
class DownloadSkipException : DownloadException {
	public this(DownloadRequest request, string message, string file = __FILE__, size_t line = __LINE__) {
		super("Skipping "~message, file, line);
	}
}
class DownloadFailException : DownloadException {
	public this(DownloadRequest request, string message, string file = __FILE__, size_t line = __LINE__) {
		super("Skipping "~message, file, line);
	}
}
unittest {
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
		execute();
		assert(pre1 && pre2 && post1 && post2);
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
		execute();
		assert(pre1 && pre2 && post1 && post2);
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
		execute();
		assert(pre1 && pre2 && !post1 && !post2);
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
		execute();
		assert(pre1 && !pre2 && !post1 && !post2);
	}
}
