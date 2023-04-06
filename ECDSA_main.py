from ecdsa import SigningKey, SECP256k1, BadSignatureError

def verify_signature(_vk, _signature, _message):
    try:
        _vk.verify(_signature, _message.encode())
        print("Verified Signature OK")
    except BadSignatureError:
        print("Error verifying signature")


'''Generate signing key using curve SECP256K1 and verifying Key'''
sk = SigningKey.generate(curve=SECP256k1)
vk = sk.verifying_key

message = "ESTAMOS EN CLASE DE CRIPTOGRAFIA"
'''Sign message'''

signature = sk.sign(message.encode())
print("Signature: ", signature.hex())

verify_signature(vk, signature, message)




