from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

digest = hashes.Hash(hashes.SHA256(), backend=default_backend()) # init hash
digest.update(b"abc") # add some data
digest.update(b"123") # add some more data
hash = digest.finalize() # close hash

print(hash)


digest_2 = hashes.Hash(hashes.SHA256(), backend=default_backend()) # init hash
digest_2.update(b"abasd") # add some data
digest_2.update(b"1234") # add some more data
hash2 = digest_2.finalize() # close hash

print(hash2)

# https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/