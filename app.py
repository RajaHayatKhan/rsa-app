from flask import Flask, render_template, request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    private_key = ""
    public_key = ""
    ciphertext = ""
    decrypted_text = ""

    if request.method == 'POST':
        if 'generate_keys' in request.form:
            # Generate key pair and update private_key and public_key
            private_key, public_key = generate_rsa_keys()

        elif 'encrypt' in request.form:
            public_key_pem = request.form.get('public_key', '')
            plaintext = request.form.get('plaintext', '')

            if public_key_pem and plaintext:
                # Encrypt the plaintext and store the result as a hex string
                ciphertext = encrypt_with_rsa(public_key_pem, plaintext)

        elif 'decrypt' in request.form:
            private_key_pem = request.form.get('private_key', '')
            ciphertext_hex = request.form.get('ciphertext', '')

            if private_key_pem and ciphertext_hex:
                # Decrypt the ciphertext and update decrypted_text
                decrypted_text = decrypt_with_rsa(private_key_pem, ciphertext_hex)

    return render_template('index.html', private_key=private_key, public_key=public_key, ciphertext=ciphertext, decrypted_text=decrypted_text)

# Helper functions for key generation, encryption, and decryption
def generate_rsa_keys():
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Serialize keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem.decode(), public_pem.decode()

def encrypt_with_rsa(public_key_pem, plaintext):
    try:
        # Deserialize the public key
        public_key = serialization.load_pem_public_key(public_key_pem.encode())

        # Encrypt the plaintext
        ciphertext = public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext.hex()  # Convert bytes to a hex string for display
    except Exception as e:
        return f"Error: {str(e)}"

def decrypt_with_rsa(private_key_pem, ciphertext_hex):
    try:
        # Deserialize the private key
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)

        # Convert the hex string back to bytes
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)

        # Decrypt the ciphertext
        plaintext = private_key.decrypt(
            ciphertext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
        return plaintext
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)
