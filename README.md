# 💎 PRISM - Complete Universal Data Converter

![PRISM Banner](https://img.shields.io/badge/PRISM-Universal--Converter-purple?style=for-the-badge)
![Bash](https://img.shields.io/badge/Language-Bash-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

**PRISM** is a powerful, high-performance, and aesthetically driven command-line toolkit designed for security researchers, CTF players, and developers. It provides a unified "single-beam" interface to decode, encode, and hash data across dozens of formats instantly.

---

## ✨ Features

- **🌈 High-End UI**: Vibrant purple-themed ASCII branding and a structured, box-style reporting layout.
- **🔍 Intelligent Auto-Detection**: Simply provide data, and PRISM automatically identifies the format (Hex, Base64, Binary, URL, etc.).
- **📂 Categorized Logical Layers**: Data is organized into three distinct sections:
  1. **Number Systems & Unicodes** (Numerical + Semantic)
  2. **Encode & Decode Transfers** (B64, B32, URL, ROT)
  3. **Cryptographic Hashes** (One-way)
- **⚡ Bulk Spectrum Analysis**: Generate comprehensive reports using the `all` or `al` commands.
- **🔄 Unicode-First Decoding**: Section 1 prioritizes mapping numerical inputs directly to Unicode characters.
- **🛡️ Dual-Endian Support**: Full support for both Big-Endian and Little-Endian in UTF-16 and UTF-32 encodings.
- **🛡️ Multi-ROT Spectrum**: Brute-force all 25 rotation shifts automatically if letters are detected.

---

## 🚀 Installation

PRISM is a portable, single-file Bash script.

```bash
# Clone the repository
git clone https://github.com/yourusername/prism.git
cd prism

# Make it executable
chmod +x conv.sh

# Move to your path for global access (optional)
sudo mv conv.sh /usr/local/bin/prism
```

### System Requirements
Requires a Linux environment with:
- `bash` (v4.0+)
- `python3`
- `xxd` (standard in most distros)
- `coreutils` (standard on Linux)

---

## 🛠 Usage & Commands

### 1. The Power Commands
| Command | Description |
| :--- | :--- |
| **`all`** | Generates a full spectrum report across ALL three categories. |
| **`al`** | Generates a focused report for only the category relevant to the input. |
| **`decoder`** | A universal translation target that extracts plaintext from any encoding. |

### 2. The Logic Rule
PRISM employs two distinct transformation strategies to ensure maximum utility:
- **Interpreted Strategy (Section 1)**: Treats numerical tokens (Hex, Dec, etc.) as **Unicode code points**. Space-separated values (e.g., `72 101`) are mapped to their respective characters (`H e`).
- **Literal Strategy (Sections 2 & 3)**: Encodings (Base64/URL) and Hashes (MD5/SHA) are performed on the **literal input string** you provided, preserving its raw transport representation.

---

## 📂 Logical Categories

### Section 1: Number Systems & Unicodes
Converts between mathematical and character representations.
*   *Hex, Binary, Decimal, Octal, ASCII, Unipoint (U+XXXX)*
*   *UTF-8, UTF-16 (BE/LE), UTF-32 (BE/LE)*

### Section 2: Encode & Decode (Transfers)
Handles data obfuscation and transfer encodings of the **literal** input.
*   *Base64, Base32, URL-Encoded, ROT1-25 Spectrum.*

### Section 3: Cryptographic Hashes
Provides standard integrity checks for the **literal** input string.
*   *MD5, SHA-1, SHA-256, SHA-384, SHA-512, CRC32.*

---

## 📖 Examples

### Unicode-First Decoding
```bash
./conv.sh "7069 636f" hex al
# Reveals the Unicode string "灩捯" (mapped from 0x7069 and 0x636F).
```

### Endianess Comparison
```bash
./conv.sh "A" al
# Shows "0041" (BE) and "4100" (LE) for UTF-16 results.
```

### Literal Encoding
```bash
./conv.sh "28777" dec all
# Section 2 shows the Base64 of the string "28777", not the decoded character.
```

### Extract Plaintext Directly
```bash
./conv.sh "48 65 6c 6c 6f" hex decoder
# Returns: Hello
```

---
*Created with ❤️ for the security community. Happy Decoding!*
