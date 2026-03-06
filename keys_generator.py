from nacl.public import PrivateKey

private_key = PrivateKey.generate()
public_key = private_key.public_key

print(f"Generated keys:\nPrivate: {private_key.encode().hex()},\nPublic: {public_key.encode().hex()}")