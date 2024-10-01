async function encryptText() {
    const algorithm = document.getElementById("algorithm").value;
    const plainText = document.getElementById("plainText").value;

    const response = await fetch('/encrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ algorithm: algorithm, plain_text: plainText })
    });

    const data = await response.json();
    document.getElementById("cipherText").textContent = data.cipher_text;
}

async function decryptText() {
    const algorithm = document.getElementById("algorithm").value;
    const cipherText = document.getElementById("cipherText").textContent;
    const key = prompt("Enter the decryption key:");

    const response = await fetch('/decrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ algorithm: algorithm, cipher_text: cipherText, key: key })
    });

    const data = await response.json();
    document.getElementById("decryptedText").textContent = data.plain_text;
}

