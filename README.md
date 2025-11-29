<p align="center">
  <img src=".github/assets/Screenshot 2025-11-23 184438.png" width="600">
</p>


# ZeroCrypt – Advanced Local Encryption Tool

---
ZeroCrypt is a local, offline encryption and password vault tool designed for secure file protection and credential storage. It provides AES-256 encryption, XOR+Salt lightweight encryption, password policy enforcement, audit logging, and an interactive command-line interface.
All data is stored locally, with no cloud interaction or telemetry.


---

Features

- AES-256 (CBC) encryption

- XOR + Salt lightweight encryption mode

- Encrypted vault storage (vault.dat)

- AES key generator

- Password policy validation (configurable via policies.cfg)

- Audit logging (audit_log.txt)

- Interactive terminal menu

- Strategy pattern for encryption modes

- In-memory vault using Map <String, PasswordEntry>

- Completely offline operation



---

## **Installation (Kali Linux or any Linux system)**

Clone the repository:

```
git clone https://github.com/haarishprajwal/ZeroCrypt.git
cd ZeroCrypt
```

Install Java (if not installed):

```
sudo apt install default-jdk
```

Compile the program:

```
javac ZeroCrypt.java
```

Run ZeroCrypt:

```
java ZeroCrypt.java
```

---

## 🐳 Run ZeroCrypt with Docker (No Java Required)

ZeroCrypt can run on **Windows, macOS, and Linux** without installing Java.
Just use Docker.

### Run ZeroCrypt from Docker Hub

```
docker run --rm -it haarishprajwal/zerocrypt
```

### Run ZeroCrypt with File Access

If you want ZeroCrypt to read/write your files (vault, keys, encrypted files),
run it from inside the folder where your files are.

**PowerShell (Windows)**
```
docker run --rm -it -v ${PWD}:/data haarishprajwal/zerocrypt
```

**CMD (Windows)**
```
docker run --rm -it -v %cd%:/data haarishprajwal/zerocrypt
```

**macOS / Linux**
```
docker run --rm -it -v "$PWD":/data haarishprajwal/zerocrypt
```

**Inside ZeroCrypt, use Linux-style paths:**
```
/data/inputfile.docx
/data/mykey.key
/data/output.enc
```

**Build from Source**
If you want to build the image locally:
```
docker build -t zerocrypt .
docker run --rm -it zerocrypt
```

---

## **CLI Menu Overview**

ZeroCrypt provides an interactive interface:

```
1) Encrypt File
2) Decrypt File
3) Generate Key
4) Switch Cipher Mode (AES/XOR)
5) Load Vault
6) Save Vault
7) Add Password Entry
8) Retrieve Password Entry
9) Delete Password Entry
10) Export Vault (CSV)
11) View Audit Log
12) Exit
```

---

## **Command-Line Usage (Optional)**

Generate an AES-256 key:

```
java ZeroCrypt genkey secret.key
```

Encrypt a file using an AES key:

```
java ZeroCrypt encrypt-file input.txt secret.key output.enc
```

Decrypt a file:

```
java ZeroCrypt decrypt-file output.enc secret.key decrypted.txt
```

---

## **Vault System**

ZeroCrypt stores structured credential entries inside an encrypted vault file (vault.dat).
Each entry includes:

Service identifier (example: github.com)

Username

Password

Timestamp


Vault data is serialized, encrypted, and written to disk using either AES or XOR+Salt depending on the selected cipher mode.


---

## **Password Policies**

Password strength validation is configurable. By default:

- Minimum length: 8

- Requires uppercase letters

- Requires digits

- Requires symbols


Policies can be modified via policies.cfg:

```
MIN_LENGTH=12
REQUIRE_UPPERCASE=true
REQUIRE_DIGIT=true
REQUIRE_SYMBOL=true
```

---

## **Encryption Modes**

- AES-256 (Recommended)

- Uses CBC mode with PKCS5 padding

- Random IV generated for each encryption

- Both vault data and individual files can be encrypted

- XOR + Salt

- Lightweight and fast

- Uses modular XOR operations with a salt array


---

## **Architecture**

ZeroCrypt uses a modular structure with a strategy-based design:

Core Components

- CipherProvider (strategy interface)

- AESCipherProvider (AES-256 implementation)

- XorCipherProvider (XOR+Salt implementation)

- PasswordEntry (serializable vault object)

- Policies (password rules parser and validator)

- AuthFailedException and WeakPasswordException


File Structure

```
ZeroCrypt/
  ZeroCrypt.java
  README.md
  policies.cfg               (optional)
  vault.dat                  (generated)
  secret.key                 (user-generated)
  audit_log.txt              (generated)
```

---

## **Security Notes**

Keep AES key files stored securely.

Do not store the vault and key file together on shared systems.

XOR mode is not intended for high-security use.

The vault file should be backed up securely after each update.



---

## **Disclaimer**

ZeroCrypt is intended for **legal, ethical, and educational use only.**
The developer is not responsible for misuse, data loss, or security incidents resulting from improper usage.


---

## **License**

ZeroCrypt is released under the MIT License.
You are free to modify, distribute, and use this software for personal or commercial purposes.


---