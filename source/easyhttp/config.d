module easyhttp.config;

struct Settings {
	string[] certPaths;
	string systemCachePath;
}
immutable Settings settings;
version(Have_easysettings) {

	import easysettings;

	shared static this() {
		settings = cast(immutable)loadSettings!Settings("herringway", SettingsFlags.none, "easyhttp");
	}
}