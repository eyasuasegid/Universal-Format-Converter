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
- **📄 Advanced Input/Output**: 
    - **`-f`**: Read data directly from files.
    - **`-o`**: Save raw results or "clean" text reports directly to disk.
    - **`|`**: Full pipeline support—pipe data in and out seamlessly.
- **🔄 Unicode-First Decoding**: Section 1 maps numerical inputs directly to Unicode characters.
- **🛡️ Dual-Endian Support**: Full support for BE and LE in UTF-16 and UTF-32 encodings.
- **🛡️ Multi-ROT/Base Spectrum**: Brute-force all rotation shifts or base encodings automatically using the `rot` and `base` universal targets.

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
| **`base`** | Displays a full spectrum of all supported base encodings. |
| **`rot`** | Brute-forces all ROT1-25 shifts AND includes ROT47. |

### 2. Flags & Pipeline
- **File Input**: `./conv.sh -f payload.txt all`
- **Output Redirection**: `./conv.sh -o result.txt "Hello" hex`
- **Piping**: `echo "SGVsbG8=" | ./conv.sh decoder`

---

## 📂 Logical Categories

### Section 1: Number Systems & Unicodes
Converts between mathematical and character representations.
*   *Hex, Binary, Decimal, Octal, ASCII, Unipoint (U+XXXX)*
*   *UTF-8, UTF-16 (BE/LE), UTF-32 (BE/LE)*
*   **Token-Aware Output**: Numerical outputs (Hex/Bin) use space-separation for clarity.

### Section 2: Encode & Decode (Transfers)
Handles data obfuscation and transfer encodings of the **literal tokens**.
*   *Base64, Base32, Base45, Base58, Base62, Base85, Base91*
*   *URL-Encoded, ROT1-25 Spectrum, ROT47.*
*   **Universal Tools**: Use `base` or `rot` to see all variations at once.

### Section 3: Cryptographic Hashes
Generates integrity checks for each **literal token** provided.
*   *MD5, SHA-1, SHA-256, SHA-384, SHA-512, CRC32.*

---

## 📖 Examples

### Universal Base Comparison
```bash
./conv.sh "Secret" base
# Shows Base64, Base32, Base58, Base91, etc., in a single categorized view.
```

### ROT47 Decoding
```bash
./conv.sh "s2E2`abP" rot47
# Returns: Data123!
```

### Chained Pipeline Processing
```bash
echo "Hello" | ./conv.sh ascii b64 | ./conv.sh b64 decoder
# Returns: Hello
```

### File-to-File Hashing
```bash
./conv.sh -f payload.bin -o checksum.sha256 sha256
# Reads payload.bin and saves the SHA256 result directly to checksum.sha256.
```

### Full Analysis Report to Disk
```bash
./conv.sh -o analysis.txt "SGVsbG8=" all
# Saves a complete, color-stripped text report of "SGVsbG8=" to analysis.txt.
```

---
*Created with ❤️ for the security community. Happy Decoding!*
