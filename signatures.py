from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend  # force reinstall if failing
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def generate_keys():
    """Generate pair of keys with rsa"""
    private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public = private.public_key()
    return private, public


def sign(message, private):
    """Create crypto signature"""
    message = bytes(str(message), 'utf-8')  # NEED TO BE BYTES, NOT STRINGS !!!!
    sig = private.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return sig


def verify(message, sig, public):
    """Verify with public key if associated private key was used to sign the message"""
    message = bytes(str(message), 'utf-8')   # NEED TO BE BYTES, NOT STRINGS !!!!
    try:
        public.verify(
            sig,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except:
        print("Error executing public_key.verify")


if __name__ == '__main__':
    pr, pu = generate_keys()
    print(pr)
    print(pu)
    message = "This is a secret message"
    sig = sign(message, pr)
    print(sig)

    # Check if verification works
    correct = verify(message, sig, pu)
    if correct:
        print("Success! Correct signature")
    else:
        print("Error! Incorrect signature")

    # Check with bad signature

    pr2, pu2 = generate_keys()
    sig2 = sign(message, pr2)
    correct = verify(message, sig2, pu)  # used pu instead of pu2
    if correct:
        print("Error! Bad signature not detected")
    else:
        print("Success! Bad signature detected")

    # Check if it detects tampered message
    badmess = message + "asd"  # corrupting original message
    correct = verify(badmess, sig, pu)
    if correct:
        print("ERROR! Tampered message not detected!")
    else:
        print("Success! Tampering detected")

# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
