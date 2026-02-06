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
- **🔄 Semantic Pivot Logic**: Seamlessly translates between formats by pivoting through intermediate states, ensuring binary integrity.
- **🛡️ Multi-ROT Spectrum**: Brute-force all 25 rotation shifts automatically if letters are detected.

---

## 🚀 Installation

PRISM is a portable, single-file Bash script.

```bash
# Clone the repository
git clone https://github.com/eyasuasegid/Prism.git
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

### 2. Numeric Spacing Rule (Section 1)
PRISM treats numbers differently based on formatting to give you maximum control:
- **Concatenated (`123456`)**: Treated as one **large numerical value**.
- **Space-Separated (`72 101 108`)**: Treated as a **sequence of ASCII bytes** (revealing "H e l").

---

## 📂 Logical Categories

### Section 1: Number Systems & Unicodes
Converts between the mathematical and character representations of data.
*   *Hex, Binary, Decimal, Octal, ASCII, Unicode, UTF-8, UTF-16, UTF-32.*

### Section 2: Encode & Decode (Transfers)
Handles data obfuscation and transfer encodings.
*   *Base64, Base32, URL-Encoded, ROT1-25 Spectrum.*
*   **Automatic ROT Detection**: If English letters are present, PRISM automatically shows all 25 rotation shifts.

### Section 3: Cryptographic Hashes
Provides standard integrity checks for the input string.
*   *MD5, SHA-1, SHA-256, SHA-384, SHA-512, CRC32.*

---

## 📖 Examples

### Auto-Detection & Categorized View
```bash
./conv.sh "SGVsbG8="
# Matches Base64 -> Shows Section 2 report with decoded output.
```

### Extract Plaintext Directly
```bash
./conv.sh "48 65 6c 6c 6f" hex decoder
# Returns: Hello
```

### Full Data Analysis
```bash
./conv.sh "U+0041" all
# Shows Number Systems, Transfers (B64/B32/ROT), and Hashes for "A".
```

### Multi-Byte Hex Conversion
```bash
./conv.sh "41 42 43" hex al
# Reveals the ASCII string "ABC" and its associated Section 1 values.
```

---
*Created with ❤️ for the security community. Happy Decoding!*
