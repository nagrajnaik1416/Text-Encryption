from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)

# AES Encryption
def aes_encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    return cipher.iv + cipher_text

def aes_decrypt(cipher_text, key):
    iv = cipher_text[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(cipher_text[AES.block_size:]), AES.block_size)
    return decrypted_text.decode()

# DES Encryption
def des_encrypt(plain_text, key):
    cipher = DES.new(key, DES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(plain_text.encode(), DES.block_size))
    return cipher.iv + cipher_text

def des_decrypt(cipher_text, key):
    iv = cipher_text[:DES.block_size]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(cipher_text[DES.block_size:]), DES.block_size)
    return decrypted_text.decode()

# RSA Encryption
def rsa_encrypt(plain_text, public_key):
    public_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key)
    cipher_text = cipher.encrypt(plain_text.encode())
    return cipher_text

def rsa_decrypt(cipher_text, private_key):
    private_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_text = cipher.decrypt(cipher_text)
    return decrypted_text.decode()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json
        algorithm = data['algorithm']
        plain_text = data['plain_text']

        if algorithm == 'aes':
            key = get_random_bytes(16)  # AES key (16 bytes for AES-128)
            cipher_text = aes_encrypt(plain_text, key)
            return jsonify({'cipher_text': cipher_text.hex(), 'key': key.hex()})
        
        elif algorithm == 'des':
            key = b'8bytekey'  # DES key (must be exactly 8 bytes)
            cipher_text = des_encrypt(plain_text, key)
            return jsonify({'cipher_text': cipher_text.hex(), 'key': key.hex()})
        
        elif algorithm == 'rsa':
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()
            cipher_text = rsa_encrypt(plain_text, public_key)
            return jsonify({
                'cipher_text': cipher_text.hex(),
                'public_key': public_key.decode(),
                'private_key': private_key.decode()
            })
        
        else:
            return jsonify({'error': 'Invalid algorithm selected'}), 400
    except Exception as e:
        logging.error(f'Encryption error: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json
        algorithm = data['algorithm']
        cipher_text = bytes.fromhex(data['cipher_text'])
        logging.debug(f"Decryption request: Algorithm: {algorithm}, Cipher Text: {data['cipher_text']}")

        if algorithm == 'aes':
            key = bytes.fromhex(data['key'])
            logging.debug(f"AES Key: {data['key']}")
            plain_text = aes_decrypt(cipher_text, key)
            return jsonify({'plain_text': plain_text})

        elif algorithm == 'des':
            key = bytes.fromhex(data['key'])
            logging.debug(f"DES Key: {data['key']}")
            plain_text = des_decrypt(cipher_text, key)
            return jsonify({'plain_text': plain_text})

        elif algorithm == 'rsa':
            private_key = data['private_key']
            logging.debug(f"Private Key: {private_key}")
            plain_text = rsa_decrypt(cipher_text, private_key)
            return jsonify({'plain_text': plain_text})

        else:
            return jsonify({'error': 'Invalid algorithm selected'}), 400
    except Exception as e:
        logging.error(f'Decryption error: {str(e)}')
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
