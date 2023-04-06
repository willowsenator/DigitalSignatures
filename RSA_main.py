from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def encrypt_message(_public_key, _message):
    return _public_key.encrypt(plaintext=_message.encode(), padding=padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))


def decrypt_message(_private_key, _enc_message):
    return _private_key.decrypt(ciphertext=_enc_message, padding=padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))


def sign_message(_private_key, _message):
    return _private_key.sign(
        _message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_sign(_sign, _public_key, _message):
    try:
        _public_key.verify(_sign, _message.encode(), padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
                           hashes.SHA256())
        print("Verified Message Signature OK")
    except InvalidSignature:
        print("Error verifying message signature")


''''Generate privateKey and publicKey'''
private_key = generate_private_key()
public_key = private_key.public_key()

message = "ESTAMOS EN CLASE DE CRIPTOGRAFIA"

'''Encrypt message'''
encMessage = encrypt_message(public_key, message)

print("Original Message: ", message)
print("Encrypted Message: ", encMessage.hex())

''''Decrypt message'''
decMessage = decrypt_message(private_key, encMessage)
print("Decrypted Message: ", decMessage.decode())

'''Sign message with PSS padding'''
signature = sign_message(private_key, message)

print("Message Signature: ", signature.hex())

'''Verify Message Signature'''
verify_sign(signature, public_key, message)
