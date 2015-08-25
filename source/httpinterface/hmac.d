module httpinterface.hmac;

private import std.digest.md : MD5;
private import std.digest.sha : SHA1;
public alias HMAC_SHA1 = HMAC!SHA1;
public alias HMAC_MD5 = HMAC!MD5;

public ubyte[] HMAC(Hash)(string inKey, string data) @safe pure nothrow {
	import std.string : representation;
	ubyte[] key = inKey.representation.dup;
	if (key.length > 64) {
		Hash hash;
		hash.start();
		hash.put(key);
		key = hash.finish();
	}
	if (key.length < 64)
		key.length = 64;

	assert(key.length == 64);
	auto ikey = key;
	auto okey = key.dup;
	ikey[] ^= 0x36; okey[] ^= 0x5C;

	assert(ikey != okey);

	Hash ihash, ohash;
	ihash.start(); ohash.start();
	ihash.put(ikey~data.representation); 
	ohash.put(okey~ihash.finish());
	ikey[] = 0; okey[] = 0; //clear keys.
	return ohash.finish().dup;
}

unittest { //Wikipedia-provided example tests
	import std.digest.md, std.digest.sha, std.string;
	assert(HMAC!MD5("","").toHexString() == "74e6f7298a9c2d168935f58c001bad88".toUpper(), "HMAC-MD5 with empty strings");
	assert(HMAC!SHA1("","").toHexString() == "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d".toUpper(), "HMAC-SHA1 with empty strings");
	assert(HMAC!MD5("key", "The quick brown fox jumps over the lazy dog").toHexString() == "80070713463e7749b90c2dc24911e275".toUpper(), "HMAC-MD5 with empty strings");
	assert(HMAC!SHA1("key", "The quick brown fox jumps over the lazy dog").toHexString() == "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9".toUpper(), "HMAC-SHA1 with empty strings");
}