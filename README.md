# 💎 PRISM - Complete Universal Data Converter

![PRISM Banner](https://img.shields.io/badge/PRISM-Universal--Converter-purple?style=for-the-badge)
![Bash](https://img.shields.io/badge/Language-Bash-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

**PRISM** is a powerful, high-performance, and aesthetically driven command-line toolkit designed for security researchers, CTF players, and developers. It provides a unified "single-beam" interface to decode, encode, and hash data across dozens of formats instantly.

---

## ✨ Features

- **🌈 High-End UI**: Vibrant purple-themed ASCII branding and a structured, box-style reporting layout.
- **🔍 Intelligent Auto-Detection**: Simply provide data, and PRISM automatically identifies the format (Hex, Base64, Binary, URL, etc.).
- **📂 Categorized Logical Layers**: Data organized into Number Systems, Transfers, and Hashes.
- **⚡ Universal Token-Aware Logic**: Space-separated tokens are processed individually across ALL sections.
- **🔄 Unicode-First Decoding**: Section 1 maps numerical inputs directly to Unicode characters.
- **🛡️ Dual-Endian Support**: Full support for BE and LE in UTF-16 and UTF-32 encodings.
- **🛡️ Multi-ROT Spectrum**: Brute-force all 25 rotation shifts automatically.

---

## 🚀 Installation

PRISM is a portable, single-file Bash script.

```bash
# Clone the repository
git clone https://github.com/eyasuasegid/prism.git
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
- `xxd`
- `coreutils`

---

## 🛠 Usage & Commands

### 1. The Power Commands
| Command | Description |
| :--- | :--- |
| **`all`** | Generates a full spectrum report across ALL three categories. |
| **`al`** | Generates a focused report for the relevant category. |
| **`decoder`** | A universal target that extracts plaintext from any encoding. |

### 2. The Logic Rule
PRISM employs two distinct transformation strategies, both of which are **Token-Aware**:
- **Interpreted Strategy (Section 1)**: Maps numerical tokens (Hex, Dec, etc.) to **Unicode code-points**. Resulting Binary and Hex values are space-separated for maximum readability.
- **Literal Strategy (Sections 2 & 3)**: Encodings (Base64/URL) and Hashes (MD5/SHA) are performed on the **literal tokens** you provided. If you provide multiple space-separated strings, each is processed independently.

---

## 📂 Logical Categories

### Section 1: Number Systems & Unicodes
Converts between mathematical and character representations.
*   *Hex, Binary, Decimal, Octal, ASCII, Unipoint (U+XXXX)*
*   *UTF-8, UTF-16 (BE/LE), UTF-32 (BE/LE)*
*   **Token-Aware Output**: Numerical outputs (Hex/Bin) use space-separation for clarity.

### Section 2: Encode & Decode (Transfers)
Handles data obfuscation and transfer encodings of the **literal tokens**.
*   *Base64, Base32, URL-Encoded, ROT1-25 Spectrum.*
*   **Batch Processing**: Provide multiple encoded blobs separated by spaces to decode them all at once.

### Section 3: Cryptographic Hashes
Generates integrity checks for each **literal token** provided.
*   *MD5, SHA-1, SHA-256, SHA-384, SHA-512, CRC32.*

---

## 📖 Examples

### Unicode-First Decoding
```bash
./conv.sh "7069 636f" hex al
# Reveals the Unicode string "灩捯" with space-separated numerical values.
```

### Batch Base64 Decoding
```bash
./conv.sh "SGVsbG8= d29ybGQ=" b64 decoder
# Returns: Hello world
```

### Multiple Token Hashing
```bash
./conv.sh "admin pass" ascii md5
# Returns MD5s for "admin" and "pass" separated by spaces.
```

### Endianess Comparison
```bash
./conv.sh "A" al
# Shows "0041" (BE) and "4100" (LE) for UTF-16.
```

---
*Created with ❤️ for the security community. Happy Decoding!*
