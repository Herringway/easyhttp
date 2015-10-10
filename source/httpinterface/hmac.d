module httpinterface.hmac;

private import std.digest.md : MD5, isDigest;
private import std.digest.sha : SHA1;
public alias HMAC_SHA1 = HMAC!SHA1;
public alias HMAC_MD5 = HMAC!MD5;
/++
 + Basic Hash Message Authentication Code algorithm.
 +
 + HMACs, like hashes, are used to verify the integrity of a given message.
 + Unlike standard hashes, HMACs also provide a guarantee of authenticity, since
 + it requires a shared key to be useful.
 +
 + Aside from the authenticity guarantee, HMACs are effectively hashes and will
 + be indistinguishable from them.
 +
 + Params:
 + Hash = The underlying hash algorithm (see std.digest.digest)
 + inKey = Key used to encode the hash
 + data = The data to be hashed
 +/
public ubyte[] HMAC(Hash)(string inKey, string data) @safe pure nothrow if (isDigest!Hash) {
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
///Wikipedia-provided example tests
unittest {
	import std.digest.md : MD5, toHexString;
	import std.digest.sha : SHA1;
	assert(HMAC!MD5("","").toHexString() == "74E6F7298A9C2D168935F58C001BAD88", "HMAC-MD5 with empty strings");
	assert(HMAC!SHA1("","").toHexString() == "FBDB1D1B18AA6C08324B7D64B71FB76370690E1D", "HMAC-SHA1 with empty strings");
	assert(HMAC!MD5("key", "The quick brown fox jumps over the lazy dog").toHexString() == "80070713463E7749B90C2DC24911E275", "HMAC-MD5 with empty strings");
	assert(HMAC!SHA1("key", "The quick brown fox jumps over the lazy dog").toHexString() == "DE7C9B85B8B78AA6BC8A7A36F70A90701C9DB4D9", "HMAC-SHA1 with empty strings");
}