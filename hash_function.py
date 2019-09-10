from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


# https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/

class someClass:
    string = None
    def __init__(self, mystring):
        self.string = mystring
    def __repr__(self):
        return self.string



class CBlock:
    data = None
    previousHash = None
    previousBlock = None
    def __init__(self, data, previousBlock):
        self.data = data
        self.previousBlock = previousBlock
        if previousBlock != None:
            self.previousHash = previousBlock.computeHash()
    def computeHash(self):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())  # init hash
        digest.update(bytes(str(self.data), 'utf8'))  # hash some data
        digest.update(bytes(str(self.previousHash), 'utf8'))  # hash previous block hash as well
        return digest.finalize()  # close hash


if __name__ == '__main__':
    root = CBlock('I am root', None)
    B1 = CBlock('I am a child.', root)
    B2 = CBlock('I am B1s brother', root)
    B3 = CBlock(12345, B1)
    B4 = CBlock(someClass('Hi there!'), B2)
    B5 = CBlock("Top block", B4)

    for b in [B1, B2, B3, B4, B5]:
        if B1.previousBlock.computeHash() == B1.previousHash:
            preint("Success! Hash is good")
        else:
            print("ERROR! Hash is not good")

    # change data without changing hash and check if blockchain detects tampering
    B3.data = 12345
    if B4.previousBlock.computeHash() == B4.previousHash:
        preint("ERROR! Tampering not detected")
    else:
        print("GOOD! Tampering detected")