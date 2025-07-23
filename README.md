# CS50P Vault: A Secure Command-Line Password Manager

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)

Video Demo: <URL HERE>

CS50P Vault is a secure, command-line password manager built entirely in Python. It provides a local, encrypted vault to store and manage sensitive credentials, combining a user-friendly, menu-driven interface with robust, modern cryptographic practices. All data is stored locally in an SQLite database file (`vault.db`), ensuring the user retains full control over their information.

The application was built with a primary focus on security and usability. It guides the user through a one-time setup process to create a master password, which then serves as the single key to unlock the vault. Once unlocked, a user can perform full CRUD (Create, Read, Update, Delete) operations on their credentials. For convenience, retrieving a password automatically copies it to the clipboard.

## Key Features

- **Master Password Protection:** A single, strong master password secures the entire vault.
- **Strong Encryption:** Utilizes industry-standard encryption for all stored credentials.
- **Full Credential Management (CRUD):** Add, retrieve, update, and delete credentials.
- **Clipboard Integration:** Retrieved passwords are automatically copied to the clipboard for convenience and security.
- **User-Friendly CLI:** A clean, menu-driven interface built with the `rich` library for an enhanced user experience.
- **Local-First Storage:** All data is stored in a local SQLite database (`vault.db`), ensuring you retain full control over your information.

## Security Deep Dive

Security is the cornerstone of this application. The following measures have been implemented to ensure the confidentiality and integrity of your data:

- **Password Hashing:** The master password is hashed using **Argon2**, a state-of-the-art, memory-hard algorithm that is highly resistant to both GPU and custom hardware attacks. It is the recommended standard for password hashing.

- **Key Derivation:** The encryption key is derived from the master password using **PBKDF2-HMAC-SHA256**. With a high iteration count (480,000), this makes brute-force attacks to discover the key computationally infeasible.

- **Data Encryption:** Credentials are encrypted using **Fernet (AES-128 in CBC mode)**, which provides symmetric, authenticated encryption. This not only keeps your data secret but also protects it from being tampered with.

- **Secure Salt Generation:** Unique, cryptographically secure salts are generated for both password hashing and key derivation, protecting against pre-computed attacks like rainbow tables.

## Installation

To get started with CS50P Vault, follow these steps:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/cs50p-project.git
    cd cs50p-project
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    # For macOS/Linux
    python3 -m venv .venv
    source .venv/bin/activate

    # For Windows
    python -m venv .venv
    .\.venv\Scripts\activate
    ```

3.  **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  **Run the application:**
    ```bash
    python src/main.py
    ```

2.  **First-Time Setup:**
    - The first time you run the vault, you will be prompted to enter your name and set a strong master password.

3.  **Main Menu:**
    - Once unlocked, you will be presented with a menu of options to manage your credentials.

    ```
     CS50P Vault Menu

     Option      Action
    ────────────────────────────────────
     1           Add a new credential
     2           Get a credential
     3           List all credentials
     4           Update a credential
     5           Delete a credential

     6           Change master password
     7           Lock vault
     8           Exit
    ```

## Project Structure

The project is organized with a clear separation of concerns, making it modular and maintainable:

```
├── src/
│   ├── main.py          # Main application entry point, UI, and user interaction
│   ├── database.py      # Handles all SQLite database interactions (CRUD operations)
│   ├── security.py      # Manages all cryptographic functions (hashing, encryption)
│   └── __init__.py
├── tests/
│   ├── test_database.py # Unit tests for the database module
│   ├── test_security.py # Unit tests for the security module
├── requirements.txt     # Project dependencies
└── README.md            # You are here!
```
