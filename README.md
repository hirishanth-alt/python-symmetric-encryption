# Python-Based Symmetric Encryption System

##1. Project Overview

This project implements and demonstrates symmetric encryption techniques using Python.

Developed as part of the Cryptographic Concepts coursework, it explores two encryption approaches: a Geffe-style Pseudorandom Number Generator (PRNG) with a stream cipher, and a custom 72-bit Substitution-Permutation Network (SPN) block cipher.

The project demonstrates encryption, decryption, keystream generation, key scheduling, confusion, diffusion, and statistical analysis through practical Python implementation.

2. Project Objectives

- Understand the principles of symmetric cryptography.
- Implement Linear Feedback Shift Registers (LFSRs).
- Develop a Geffe-style nonlinear PRNG.
- Implement stream cipher encryption and decryption.
- Design a custom Substitution-Permutation Network block cipher.
- Implement Counter (CTR) mode.
- Analyse cipher behaviour through statistical testing.

3. Implemented Features

 # A. PRNG and Stream Cipher

- Three Linear Feedback Shift Registers (LFSRs) with lengths of 7, 9 and 11 bits.
- Geffe-style nonlinear combining function.
- Pseudorandom keystream generation.
- XOR-based encryption and decryption.
- Worked encryption example displaying plaintext, keystream and ciphertext in binary and hexadecimal formats.

 # B. Custom Block Cipher

- 72-bit (9-byte) block structure.
- Four-round Substitution-Permutation Network (SPN).
- Deterministically generated 8-bit S-box.
- 72-bit bit-level permutation.
- Round key generation and key scheduling.
- Confusion and diffusion operations.
- PKCS#7-style padding for the direct block encryption demonstration.

 # C. Counter (CTR) Mode

- Seven-byte nonce and two-byte counter.
- Keystream generation using the block cipher.
- XOR-based encryption and decryption.
- No padding required for CTR mode.

 # D. Statistical Analysis

- Key-bit sensitivity testing.
- Hamming distance calculation.
- Avalanche effect evaluation.
- Round-adjustment testing from 1 to 6 rounds.
- Comparison of ciphertext bit changes.

4. Technologies Used

- Python 3
- Python Random Module
- Bitwise Operations
- XOR and AND Operations
- Binary and Hexadecimal Representations
- Symmetric Cryptography Concepts

5. Project Structure

```
python-symmetric-encryption/
│
├── README.md
│
└── ciphers.py
```

6. How to Run the Project

 # Requirements
- Python 3.x
- No external libraries required.

 # Execution

 1. Clone the repository:

```
git clone YOUR_REPOSITORY_URL
```

 2. Navigate to the project directory:

```
cd python-symmetric-encryption
```

 3. Execute the Python program:

```
python3 ciphers.py
```

The program automatically executes the demonstrations and displays the encryption, decryption and statistical testing results.

7. Experimental Results

The implementation demonstrates:

- Successful stream cipher encryption and decryption.
- Successful block cipher encryption and decryption.
- Successful CTR mode encryption and decryption.
- An observed 54.0% ciphertext bit change when one master-key bit is flipped in the four-round experiment.
- Comparison of ciphertext changes across different round configurations.

These results demonstrate the behaviour of the implemented algorithms under the selected test conditions; they do not establish cryptographic security.

8. Learning Outcomes

Through this project, I gained practical experience in:

- Understanding symmetric encryption mechanisms.
- Implementing cryptographic concepts using Python.
- Working with binary data and bitwise operations.
- Understanding pseudorandom number generation.
- Applying confusion and diffusion principles.
- Evaluating encryption behaviour through statistical experiments.

9. Limitations and Disclaimer

This project is developed for educational purposes.

The Geffe-style generator is susceptible to known correlation attacks, and the custom SPN cipher has not undergone independent cryptographic security analysis.

These implementations are not suitable for protecting real-world sensitive information. Production systems should use established, independently reviewed cryptographic standards and authenticated encryption.
