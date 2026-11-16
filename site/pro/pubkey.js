// The PUBLIC key that checks Pro licence keys in the browser. It is not set yet (null), so no licence
// unlocks anything and the Pro page says so. `python tools/make_license.py init` makes the key pair on the
// owner's computer and writes the public half here. The private half never enters this repository.
window.HCProKey = { publicKeyHex: null };
