module httpinterface.downloadmanager;

import httpinterface.http;

import std.concurrency, std.functional;

struct DownloadRequest {
	RequestType Request;
	string DestPath;
	void delegate(DownloadRequest request, QueueDetails qd) PostDownload;
	void delegate(DownloadRequest request, QueueDetails qd) PreDownload;
	void delegate(DownloadRequest request, QueueDetails qd) onError;
}
struct QueueDetails {
	ulong ID;
	ulong Count;
}
struct DownloadError {
	size_t ID;
	string msg;
}
struct QueuedDownload {
	size_t ID;
	HTTPRequest Request;
	string DestPath;
}
struct DownloadManager {
	uint QueueCount = 4;
	private DownloadRequest[] Queue;
	void delegate(DownloadRequest request, QueueDetails qd) PostDownloadFunction;
	void delegate(DownloadRequest request, QueueDetails qd) PreDownloadFunction;
	void add(DownloadRequest request) nothrow {
		Queue ~= request;
	}
	void execute() nothrow {
		scope(failure) return;
		auto downloaders = new Tid[](QueueCount);
		foreach (ref downloader; downloaders)
			downloader = spawn(&downloadRoutine, thisTid);
		foreach (id, item; Queue) {
			receive(
				(bool isReady, Tid child) {
					if (isReady) {
						if (PreDownloadFunction)
							PreDownloadFunction(item, QueueDetails(id, Queue.length));
						if (item.PreDownload)
							item.PreDownload(item, QueueDetails(id, Queue.length));
					//	send(child, immutable QueuedDownload(id, item.Request, item.DestPath));
					}
				},
				(size_t idSuccess) {
					if (PostDownloadFunction)
						PostDownloadFunction(item, QueueDetails(idSuccess, Queue.length));
					if (Queue[idSuccess].PostDownload)
						Queue[idSuccess].PostDownload(item, QueueDetails(idSuccess, Queue.length));
				},
				(DownloadError error) {
					if (Queue[error.ID].onError)
						Queue[error.ID].onError(item, QueueDetails(error.ID, Queue.length));
				}
			);
		}
	}
}
void downloadRoutine(Tid parent) {
	while (true) {
		send(parent, true, thisTid);
		receive(
			(QueuedDownload download) {
				try { 
					//send(parent, download.ID);
				} catch (Exception e) {
					//send(parent, immutable DownloadError(download.ID, e.msg));
				}
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