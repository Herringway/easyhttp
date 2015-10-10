module easyhttp.downloadmanager;
version(downloadmanager) {
	import easyhttp.http;

	import std.concurrency, std.functional;

	struct DownloadRequest {
		RequestType request;
		string destPath;
		void delegate(DownloadRequest request, QueueDetails qd) postDownload;
		void delegate(DownloadRequest request, QueueDetails qd) preDownload;
		void delegate(DownloadRequest request, QueueDetails qd) onError;
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
		RequestType request;
		string destPath;
	}
	struct DownloadManager {
		uint queueCount = 4;
		private DownloadRequest[] queue;
		void delegate(DownloadRequest request, QueueDetails qd) postDownloadFunction;
		void delegate(DownloadRequest request, QueueDetails qd) preDownloadFunction;
		void add(DownloadRequest request) nothrow {
			queue ~= request;
		}
		void execute() nothrow {
			scope(failure) return;
			auto downloaders = new Tid[](queueCount);
			foreach (ref downloader; downloaders)
				downloader = spawn(&downloadRoutine, thisTid);
			foreach (id, item; queue) {
				receive(
					(bool isReady, Tid child) {
						if (isReady) {
							if (preDownloadFunction)
								preDownloadFunction(item, QueueDetails(id, queue.length));
							if (item.preDownload)
								item.preDownload(item, QueueDetails(id, queue.length));
						//	send(child, immutable QueuedDownload(id, item.request, item.destPath));
						}
					},
					(size_t idSuccess) {
						if (postDownloadFunction)
							postDownloadFunction(item, QueueDetails(idSuccess, queue.length));
						if (queue[idSuccess].postDownload)
							queue[idSuccess].postDownload(item, QueueDetails(idSuccess, queue.length));
					},
					(DownloadError error) {
						if (queue[error.ID].onError)
							queue[error.ID].onError(item, QueueDetails(error.ID, queue.length));
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
}