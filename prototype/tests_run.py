import copy
from ledger.chain import Chain, new_key
from ledger.verify import verify

key = new_key()
c = Chain(key)
for i in range(5):
    c.append("shop", "read", f"Rs {23999 - i}")
pub = key.public_key()
base = c.entries

print("untouched      :", verify(base, pub))

e = copy.deepcopy(base); e[2]["result"] = "Rs 1"
print("edit step 2    :", verify(e, pub))

e = copy.deepcopy(base); del e[2]
print("delete step 2  :", verify(e, pub))

e = copy.deepcopy(base); e[1], e[2] = e[2], e[1]
print("reorder 1,2    :", verify(e, pub))

other = new_key().public_key()
print("wrong pub key  :", verify(base, other))

e = copy.deepcopy(base); e[3]["sig"] = e[1]["sig"]
print("swap signature :", verify(e, pub))

print("truncate last 2:", verify(base[:-2], pub), "(needs anchor to catch)")
