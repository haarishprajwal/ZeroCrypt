# ZeroCrypt – Advanced Local Encryption Tool

ZeroCrypt is an aggressive, fast, and secure local file encryption CLI tool built for developers, cybersecurity learners, and privacy-focused users.
It uses AES-256 and XOR+Salt encryption with a modular OOP architecture and a hacker-grade command-line interface.


---

🚀 Features

🔐 AES-256 encryption

⚡ Optional XOR + Salt lightweight mode

🗂 Encrypted vault file (vault.dat)

🔑 Secure key generation

🔍 Password strength validation (regex-based)

🧾 Audit logging (audit_log.txt)

🧩 Strategy + Factory design patterns

🗃 Map-based in-memory vault

🔒 Fully offline, no telemetry



---

📦 Installation

Clone the repository

git clone https://github.com/yourname/ZeroCrypt.git
cd ZeroCrypt

Compile

javac ZeroCrypt.java

Run

java ZeroCrypt


---

🖥 CLI Menu

On startup, ZeroCrypt shows a menu like:

1) Encrypt File
2) Decrypt File
3) Generate Key
4) View Audit Log
5) Exit


---

🔧 Commands

Encrypt a file

java ZeroCrypt encrypt input.txt secret.key output.enc

Decrypt a file

java ZeroCrypt decrypt file.enc secret.key decrypted.txt

Generate a key

java ZeroCrypt genkey secret.key


---

🧩 Architecture Overview

Core Classes

Vault (abstract) – add, retrieve, delete, export

Cipher (interface) – encrypt/decrypt

XorCipher – fast XOR + salt encryption

AESCipher – AES-256 implementation

PasswordEntry – serialized objects stored in the vault


Collections

Map<String, PasswordEntry> – the in-memory storage


Custom Exceptions

AuthFailedException

WeakPasswordException



---

🔐 Encryption Concepts

AES-256 (recommended)

Strong symmetric encryption for highly sensitive files.

XOR + Salt (educational mode)

Uses modular arithmetic:

cipher[i] = data[i] XOR salt[i % saltLength]


---

🔣 Password Strength Rules

Validated using regex:

Contains uppercase

Contains digits

Contains symbols

Minimum length (configurable via policies.cfg)



---

📚 Math Inside

Modular arithmetic for XOR cipher

Entropy calculation for password strength

Entropy ≈ log₂(charsetⁿ)



---

🏗 Design Patterns Used

Strategy Pattern → choose between AES or XOR

Factory Pattern → storage/encryption provider abstraction



---

📁 File Summary

File	Description

ZeroCrypt.java	Main CLI program
vault.dat	Encrypted vault
policies.cfg	Password policy rules
audit_log.txt	Operation logs



---

⚠ Disclaimer

ZeroCrypt is intended only for legal, ethical, and educational use.
Misuse may violate security or privacy laws.


---

🤝 Contributing

Pull requests, improvements, and feature suggestions are welcome!


---

⭐ License

MIT License — free for personal and commercial use.
