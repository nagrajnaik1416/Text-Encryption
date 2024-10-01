
# Text Encryption and Decryption Tool

This is a web-based Text Encryption and Decryption Tool built using Flask, providing encryption and decryption functionalities with AES, DES, and RSA algorithms. It allows users to securely encrypt and decrypt text through a simple web interface.

## Table of Contents

- [Features](#features)
- [Technologies Used](#technologies-used)
- [Installation](#installation)
- [API Endpoints](#api-endpoints)
- [Usage](#usage)
- [License](#license)

## Features

- **Encryption algorithms supported**:
  - AES (Advanced Encryption Standard)
  - DES (Data Encryption Standard)
  - RSA (Rivest-Shamir-Adleman)
- Provides both encryption and decryption functionalities for text.
- Generates a random key for AES and DES encryption.
- Includes key generation for RSA encryption.
- Simple API interface to perform encryption and decryption through HTTP requests.
- User-friendly web interface to select an encryption algorithm and input the text.

## Technologies Used

- **Flask** – Web framework to manage routing and requests.
- **PyCryptodome** – Cryptography library for AES, DES, and RSA encryption.
- **JavaScript** – Handles client-side interactions and API requests.
- **HTML/CSS** – For the front-end interface.


## Installation

### 1. Clone the Repository

```
https://github.com/nagrajnaik1416/Text-Encryption.git
cd Text-Encryption
```

## Installation

### 2. Install Dependencies

Make sure you have Python 3.x installed. Then, install the required Python libraries using `pip`:

```
pip install -r requirements.txt
```

### 3. Run the Application

Start the Flask application by running:

```
python app.py
```
By default, the app will run on `http://127.0.0.1:5000/`

### API Endpoints

`/encrypt`
Method: `POST`
Description: Encrypts the given text using the selected algorithm.
Request Body :
```
{
  "algorithm": "aes" | "des" | "rsa",
  "plain_text": "Your text here"
}
```
Response :
```
{
  "cipher_text": "Encrypted text in hex",
  "key": "Key used (in hex)",  // For AES/DES
  "public_key": "RSA public key",  // For RSA
  "private_key": "RSA private key"  // For RSA
}
```
`/decrypt`
Method: `POST`
Description: Decrypts the given cipher text using the selected algorithm.

Request Body :
```
{
  "algorithm": "aes" | "des" | "rsa",
  "cipher_text": "Cipher text in hex",
  "key": "Key in hex (for AES/DES)" | "private_key" (for RSA)
}
```
Response :
```
{
  "plain_text": "Decrypted text"
}
```
## Usage
1. Open your browser and navigate to `http://127.0.0.1:5000/`.
2. Select the desired encryption algorithm (AES, DES, or RSA).
3. Input the text you want to encrypt and click the "Encrypt" button.
4. You will receive the encrypted text and the key used for encryption (for AES/DES) or the public/private keys for RSA.
5. For decryption, input the cipher text and the corresponding key/private key and click "Decrypt" to retrieve the original text.

## License
This project is licensed under the MIT License. See the LICENSE file for details.




