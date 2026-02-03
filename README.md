# 💎 PRISM - Advanced Data Converter

![PRISM Banner](https://img.shields.io/badge/PRISM-Data--Converter-purple?style=for-the-badge)

**PRISM** is a high-performance, aesthetically pleasing command-line toolkit designed for security researchers and developers. It provides a "single-beam" interface to transform data between dozens of formats, encodings, and hashes instantly.

## ✨ Features

- **🌈 High-End UI**: Unique purple-themed ASCII branding and box-structured reporting.
- **🛡️ Direct vs. Interpreted Logic**: Purely logical separation between literal string transformations and semantic/decoded value conversions.
- **🔍 Intelligent Auto-Detection**: Give PRISM data, and it will guess the format (Hex, Base64, Binary, URL, etc.) automatically.
- **📦 Zero Dependency Design**: No `pip install` required. Uses native system tools and Python standard libraries.
- **🧩 Pivot Logic**: Seamlessly converts between formats that don't directly support each other by pivoting through Hex/ASCII intermediate states.
- **⚡ Bulk Conversion**: Use the `all` flag to see the entire spectrum of your data in one view.

---

## 🚀 Installation

PRISM is a portable, single-file bash script.

```bash
# Clone the repository (if applicable) or download conv.sh
chmod +x conv.sh

# Move to your path for global access (optional)
sudo mv conv.sh /usr/local/bin/prism
```

### System Requirements
Requires a Linux or macOS environment with:
- `bash` (v4.0+)
- `python3`
- `xxd` (usually in `vim-common`)
- `coreutils` (standard on Linux)

---

## 🛠 Usage

### 1. Auto-Detection (Fastest)
Let PRISM figure out what your data is and show the decoded ASCII.
```bash
./conv.sh SGVsbG8gV29ybGQ=
```

### 2. Bulk Spectrum Report
View every possible transformation for a piece of data.
```bash
./conv.sh "414243" hex all
```

### 3. Targeted Conversion
Convert specifically from one format to another.
```bash
./conv.sh "Hello" ascii base64
./conv.sh "U+0041 U+0042" unicode hex
```

### 4. Direct Hashing
Hash the input characters directly.
```bash
./conv.sh "secret_password" md5
```

---

## 📂 Supported Formats

| Category | Formats |
| :--- | :--- |
| **Standards** | Hex, Base64, Base32, Binary, Decimal, Octal, URL-Encoded, ROT13, ASCII |
| **Encoders** | UTF-8, UTF-16, UTF-32, Unicode (U+XXXX) |
| **Hashes** | MD5, SHA1, SHA256, SHA384, SHA512, CRC32 |

---

## 💡 Why PRISM?

In data analysis and security auditing, you often find a string and don't know if you should hash the encoded string itself or its decoded content. **PRISM** solves this by providing:
1. **Direct Transformations**: What the string looks like (literal).
2. **Interpreted Conversions**: What the data means (semantic).

---
*Created with ❤️ for the security community.*
