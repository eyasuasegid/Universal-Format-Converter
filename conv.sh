#!/bin/bash
# PRISM - Complete Universal Converter 
# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# Check for required tools
check_dependencies() {
    local missing=()
    for tool in xxd python3 awk sed tr md5sum; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}Error: The following required tools are missing:${NC}"
        for m in "${missing[@]}"; do echo "  - $m"; done
        echo -e "${YELLOW}Please install them to use PRISM.${NC}"
        exit 1
    fi
}

# Function to normalize format names
normalize_format() {
    case "$1" in
        hex|hexadecimal|h) echo "hex" ;;
        ascii|text|a) echo "ascii" ;;
        bin|binary|b) echo "bin" ;;
        dec|decimal|d) echo "dec" ;;
        oct|octal|o) echo "oct" ;;
        base32|b32) echo "base32" ;;
        base64|b64) echo "base64" ;;
        url|percent) echo "url" ;;
        unicode|uni|u) echo "unicode" ;;
        rot) echo "rot" ;;
        rot13) echo "rot13" ;;
        rot[0-9]|rot1[0-9]|rot2[0-5]) echo "$1" ;;
        decoder|decode) echo "decoder" ;;
        utf8|utf-8) echo "utf8" ;;
        utf16|utf-16) echo "utf16" ;;
        utf32|utf-32) echo "utf32" ;;
        all) echo "all" ;;
        al) echo "al" ;;
        # Hashes
        md5) echo "md5" ;;
        sha1) echo "sha1" ;;
        sha256) echo "sha256" ;;
        sha384) echo "sha384" ;;
        sha512) echo "sha512" ;;
        crc32) echo "crc32" ;;
        *) echo "$1" ;;
    esac
}

# Function to identify section ID
get_section_id() {
    local fmt=$(normalize_format "$1")
    case "$fmt" in
        hex|bin|dec|oct|ascii|unicode|utf8|utf16|utf32) echo 1 ;;
        base64|base32|rot*|url|decoder) echo 2 ;;
        md5|sha1|sha256|sha384|sha512|crc32) echo 3 ;;
        *) echo 1 ;; # Default to Section 1
    esac
}

# Function to get section name
get_section_name() {
    case "$1" in
        1) echo "Section 1: Number Systems & Unicodes" ;;
        2) echo "Section 2: Encode & Decode (Transfers)" ;;
        3) echo "Section 3: Cryptographic Hashes" ;;
    esac
}

# Section Printing Functions
print_section_header() {
    local from="$1"
    local input="$2"
    local target="$3"
    local src_name="$4"
    echo -e "${PURPLE}┌──────────────────────────────────────────────────${NC}"
    echo -e "${PURPLE}│${NC} ${BOLD}Converting  ${NC} : ${CYAN}$from${NC} ${PURPLE}→${NC} ${CYAN}$target${NC}"
    echo -e "${PURPLE}│${NC} ${BOLD}Source Input${NC} : ${YELLOW}$input${NC}"
    echo -e "${PURPLE}│${NC} ${BOLD}Source Sect.${NC} : ${CYAN}$src_name${NC}"
    echo -e "${PURPLE}├──────────────────────────────────────────────────${NC}"
    echo ""
}

print_section_1() {
    local input="$1"
    local from="$2"
    echo -e "${BOLD}${PURPLE}┌── SECTION 1: Number Systems & Unicodes${NC}"
    
    # Decode first (Interpreted Meaning)
    { dec_res=$(perform_conversion "$input" "$from" "decoder"); } 2>/dev/null
    if [ -n "$dec_res" ] && [ "$from" != "ascii" ]; then
        printf "${PURPLE}│${NC}  ${YELLOW}[DECODE]${NC}      : ${BOLD}${GREEN}%s${NC}\n" "$dec_res"
        echo -e "${PURPLE}│${NC}"
    fi

    # List items in Section 1
    printf "${PURPLE}│${NC}  ${YELLOW}[Numerical Value]${NC}\n"
    for fmt in dec hex oct bin; do
        if [ "$fmt" == "$from" ]; then label="$fmt (Source)"; else label="$fmt"; fi
        { res=$(perform_conversion "$input" "$from" "$fmt"); } 2>/dev/null
        if [ -n "$res" ]; then printf "${PURPLE}│${NC}  ${CYAN}▸ %-15s${NC} : ${GREEN}%s${NC}\n" "$label" "$res"; fi
    done
    echo -e "${PURPLE}│${NC}"

    printf "${PURPLE}│${NC}  ${YELLOW}[Unicode & Text]${NC}\n"
    { ascii_val=$(perform_conversion "$input" "$from" "ascii"); } 2>/dev/null
    printf "${PURPLE}│${NC}  ${CYAN}▸ %-15s${NC} : ${GREEN}%s${NC}\n" "ascii/plain" "$ascii_val"
    for fmt in unicode utf8 utf16 utf32; do
         if [ "$fmt" == "$from" ]; then label="$fmt (Source)"; else label="$fmt (Encoded)"; fi
         { res=$(perform_conversion "$input" "$from" "$fmt"); } 2>/dev/null
         if [ -n "$res" ]; then printf "${PURPLE}│${NC}  ${CYAN}▸ %-15s${NC} : ${GREEN}%s${NC}\n" "$label" "$res"; fi
    done
    echo -e "${PURPLE}└──────────────────────────────────────────────────${NC}"
}

print_section_2() {
    local input="$1"
    local from="$2"
    echo -e "${BOLD}${PURPLE}┌── SECTION 2: Encode & Decode (Transfers)${NC}"
    # Decode first
    { dec_res=$(perform_conversion "$input" "$from" "decoder"); } 2>/dev/null
    if [ -n "$dec_res" ]; then
        printf "${PURPLE}│${NC}  ${YELLOW}[DECODE]${NC}      : ${BOLD}${GREEN}%s${NC}\n" "$dec_res"
        echo -e "${PURPLE}│${NC}"
    fi

    printf "${PURPLE}│${NC}  ${YELLOW}[ENCODE / NAME]${NC}\n"
    for fmt in base64 base32 url; do
         if [ "$fmt" == "$from" ]; then 
            # Re-encode as per user instruction "encode is its name"
            { res=$(perform_conversion "$input" "$from" "$fmt"); } 2>/dev/null
            label="$fmt (Self-Enc)"
         else 
            { res=$(perform_conversion "$input" "ascii" "$fmt"); } 2>/dev/null
            label="$fmt"
         fi
         printf "${PURPLE}│${NC}  ${CYAN}▸ %-15s${NC} : ${GREEN}%s${NC}\n" "$label" "$res"
    done
    
    # ROT Section
    printf "${NC}${PURPLE}│${NC}\n"
    printf "${PURPLE}│${NC}  ${YELLOW}[ROTATION CIPHERS]${NC}\n"
    
    # User Request: Use the original input for rotation, not the decoded one.
    # Also, if no letters, just print itself (once).
    if [[ ! "$input" =~ [A-Za-z] ]]; then
        printf "${PURPLE}│${NC}  ${CYAN}▸ %-15s${NC} : ${GREEN}%s${NC}\n" "rot (N/A)" "$input"
    else
        for i in $(seq 1 25); do
            { res=$(perform_rot "$input" "$i"); } 2>/dev/null
            label="rot-$i"
            if [ "$from" == "rot$i" ]; then label="$label (Source)"; 
            elif [ "$i" -eq 13 ]; then
                if [ "$from" == "rot13" ]; then label="rot13 (Source)"; else label="rot13"; fi
            fi
            printf "${PURPLE}│${NC}  ${CYAN}▸ %-15s${NC} : ${GREEN}%s${NC}\n" "$label" "$res"
        done
    fi
    echo -e "${PURPLE}└──────────────────────────────────────────────────${NC}"
}

print_section_3() {
    local input="$1"
    local from="$2"
    echo -e "${BOLD}${PURPLE}┌── SECTION 3: Cryptographic Hashes${NC}"
    for fmt in md5 sha1 sha256 sha512 crc32; do
         res=$(hash_string "$input" "$fmt")
         printf "${PURPLE}│${NC}  ${CYAN}▸ %-15s${NC} : ${GREEN}%s${NC}\n" "$fmt" "$res"
    done
    echo -e "${PURPLE}└──────────────────────────────────────────────────${NC}"
}

# Caesar Cipher Helper
perform_rot() {
    local input="$1"
    local shift="$2"
    # Create the shifted alphabets
    local upper="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local lower="abcdefghijklmnopqrstuvwxyz"
    local shifted_upper="${upper:shift}${upper:0:shift}"
    local shifted_lower="${lower:shift}${lower:0:shift}"
    echo "$input" | tr "${upper}${lower}" "${shifted_upper}${shifted_lower}"
}

# Function to clean input
clean_input() {
    local input="$1"
    local format="$2"
    
    case "$format" in
        hex)
            echo "$input" | tr -d ' \n\r' | sed 's/0x//g; s/[^0-9a-fA-F]//g' | tr '[:upper:]' '[:lower:]'
            ;;
        bin)
            echo "$input" | tr -cd '01' | sed 's/ //g'
            ;;
        dec)
            echo "$input" | tr -cd '0-9 ' | sed 's/  */ /g'
            ;;
        oct)
            echo "$input" | tr -cd '0-7 ' | sed 's/  */ /g'
            ;;
        base32)
            echo "$input" | tr '[:lower:]' '[:upper:]' | tr -cd 'A-Z2-7'
            ;;
        base64)
            echo "$input" | tr -cd 'A-Za-z0-9+/'
            ;;
        url)
            echo "$input" | sed 's/%/\\x/g'
            ;;
        unicode)
             echo "$input" | sed 's/[Uu]+//g; s/0x//g; s/,/ /g' | tr -cd '0-9a-fA-F '
             ;;
        utf8|utf16|utf32)
             # These are hex representations
             echo "$input" | tr -d ' \n\r' | sed 's/0x//g; s/[^0-9a-fA-F]//g' | tr '[:upper:]' '[:lower:]'
             ;;
        *)
            echo "$input"
            ;;
    esac
}

# Conversion functions
hex_to_ascii() {
    local hex="$1"
    if [ $(( ${#hex} % 2 )) -eq 1 ]; then
        hex="0$hex"
    fi
    echo -n "$hex" | xxd -r -p 2>/dev/null || python3 -c "
import sys, binascii
try:
    print(binascii.unhexlify(sys.argv[1]).decode(), end='')
except:
    print('', end='')
" "$hex"
}

ascii_to_hex() {
    if [ -n "$1" ]; then echo -n "$1"; else cat; fi | xxd -p | tr -d '\n'
}

bin_to_ascii() {
    local hex=$(bin_to_hex "$1")
    hex_to_ascii "$hex"
}

# NEW: Optimized ascii_to_bin that removes unnecessary leading zeros
ascii_to_bin() {
    if [ -n "$1" ]; then echo -n "$1"; else cat; fi | xxd -b -c 256 | sed 's/^.*: //; s/  .*//' | tr -d ' \n'
}

dec_to_ascii() {
    local hex=$(dec_to_hex "$1")
    hex_to_ascii "$hex"
}

ascii_to_dec() {
    if [ -n "$1" ]; then echo -n "$1"; else cat; fi | xxd -p | sed 's/../& /g' | tr ' ' '\n' | while read hex; do
        [ -n "$hex" ] && printf "%d " "0x$hex"
    done | sed 's/ $//'
}

oct_to_ascii() {
    local hex=$(for num in $1; do printf "%02x" "0$num"; done)
    hex_to_ascii "$hex"
}

# FIXED: Parsing
# FIXED: helper for oct_to_bin
# FIXED: Safe implementations using hex intermediate
ascii_to_oct() {
    local stream
    if [ -n "$1" ]; then stream=$(echo -n "$1"); else stream=$(cat); fi
    for hex in $(echo -n "$stream" | xxd -p | sed 's/../& /g'); do
        printf "%03o " "0x$hex"
    done | sed 's/ $//'
}

oct_to_bin() {
    python3 -c "import sys; print(bin(int(sys.argv[1], 8))[2:], end='')" "${1// /}" 2>/dev/null
}

# NEW: Unicode Helpers
ascii_to_unicode() {
    # If explicit arg, echo it. Else assume stdin.
    if [ -n "$1" ]; then echo -n "$1"; else cat; fi | python3 -c "
import sys
chars = sys.stdin.read()
print(' '.join([f'U+{ord(c):04X}' for c in chars]), end='')
"
}

unicode_to_ascii() {
    # Expects space separated hex string (e.g., 0041 0042)
    if [ -n "$1" ]; then echo -n "$1"; else cat; fi | python3 -c "
import sys
try:
    code_points = sys.stdin.read().split()
    print(''.join([chr(int(cp, 16)) for cp in code_points]), end='')
except: pass
"
}

# NEW: Generic Python Encoding Helper (Text <-> Hex)
text_to_encoded_hex() {
    local codec="$1"
    # Read raw bytes from stdin, treat as Latin-1 (1:1 byte mapping) to get string, then encode
    python3 -c "
import sys
try:
    data = sys.stdin.buffer.read()
    # Decode input bytes to string using latin-1 (safest 1:1 mapping)
    text = data.decode('latin-1')
    # Encode to target codec and print hex
    print(text.encode('$codec').hex(), end='')
except Exception as e:
    print(f'Error: {str(e)}')
"
}

encoded_hex_to_text() {
    local codec="$1"
    local hex="$2"
    echo -n "$hex" | python3 -c "import sys; print(bytes.fromhex(sys.stdin.read().strip()).decode('$codec', errors='ignore'), end='')"
}

# FIXED: bin_to_hex with dynamic padding
bin_to_hex() {
    local bin="$1"
    # Remove spaces
    bin=$(echo "$bin" | tr -d ' ')
    # Calculate how many bits we need to pad to make complete bytes
    local len=${#bin}
    if [ $((len % 8)) -ne 0 ]; then
        padding=$((8 - (len % 8)))
        bin=$(printf "%0${padding}d%s" 0 "$bin")
    fi
    # Convert each byte (8 bits) to hex
    for ((i=0; i<${#bin}; i+=8)); do
        byte="${bin:i:8}"
        printf "%02x" $((2#$byte))
    done
}

# FIXED: hex_to_bin - remove leading zeros
hex_to_bin() {
    local hex="$1"
    # Ensure even length
    if [ $(( ${#hex} % 2 )) -eq 1 ]; then
        hex="0$hex"
    fi
    # Efficiently convert to binary stream using xxd (strip offsets and ASCII dump)
    echo -n "$hex" | xxd -r -p 2>/dev/null | xxd -b -c 256 | sed 's/^.*: //; s/  .*//' | tr -d ' \n'
}

dec_to_hex() {
    local input="$1"
    if [[ "$input" =~ " " ]]; then
        for num in $input; do
            printf "%02x" "$num"
        done
    else
        python3 -c "import sys; print(hex(int(sys.argv[1]))[2:], end='')" "$input" 2>/dev/null
    fi
}

hex_to_dec() {
    python3 -c "import sys; print(int(sys.argv[1].replace(' ', ''), 16), end='')" "$1" 2>/dev/null
}

byte_hex_to_dec() {
    local hex="$1"
    [ $(( ${#hex} % 2 )) -eq 1 ] && hex="0$hex"
    for ((i=0; i<${#hex}; i+=2)); do
        printf "%d " "0x${hex:i:2}"
    done | sed 's/ $//'
}

byte_hex_to_oct() {
    local hex="$1"
    [ $(( ${#hex} % 2 )) -eq 1 ] && hex="0$hex"
    for ((i=0; i<${#hex}; i+=2)); do
        printf "%03o " "0x${hex:i:2}"
    done | sed 's/ $//'
}

byte_hex_to_bin() {
    local hex="$1"
    [ $(( ${#hex} % 2 )) -eq 1 ] && hex="0$hex"
    for ((i=0; i<${#hex}; i+=2)); do
        # 8-bit padded bin for clear per-byte view
        printf "%08d " $(python3 -c "print(bin(int('${hex:i:2}', 16))[2:])")
    done | sed 's/ $//'
}

bin_to_dec() {
    python3 -c "import sys; print(int(sys.argv[1].replace(' ', ''), 2), end='')" "$1" 2>/dev/null
}

dec_to_bin() {
    local input="$1"
    if [[ "$input" =~ " " ]]; then
        for num in $input; do
            printf "%08d" $(python3 -c "print(bin(int($num))[2:])")
        done
    else
        python3 -c "import sys; print(bin(int(sys.argv[1]))[2:], end='')" "$1" 2>/dev/null
    fi
}




# NEW: Hashing Function
hash_string() {
    local input="$1"
    local algo="$2"
    
    case "$algo" in
        md5)    echo -n "$input" | md5sum | awk '{print $1}' ;;
        sha1)   echo -n "$input" | sha1sum | awk '{print $1}' ;;
        sha256) echo -n "$input" | sha256sum | awk '{print $1}' ;;
        sha384) echo -n "$input" | sha384sum | awk '{print $1}' ;;
        sha512) echo -n "$input" | sha512sum | awk '{print $1}' ;;
        crc32)  echo -n "$input" | crc32 /dev/stdin ;;
    esac
}

# Advanced Hashing (takes hex representation)
hash_hex() {
    local hex="$1"
    local algo="$2"
    if [ "$algo" == "crc32" ]; then
        echo -n "$hex" | xxd -r -p | crc32 /dev/stdin
    else
        echo -n "$hex" | xxd -r -p | ${algo}sum | awk '{print $1}'
    fi
}

# Internal function to perform conversion without UI output
perform_conversion() {
    local input="$1"
    local from="$2"
    local to="$3"
    
    # Pre-clean input
    local cleaned=$(clean_input "$input" "$from")
    
    case "$from.$to" in
        # ASCII Conversions
        ascii.ascii) echo "$input" ;;
        ascii.hex) ascii_to_hex "$input" ;;
        ascii.bin) ascii_to_bin "$input" ;;
        ascii.dec) ascii_to_dec "$input" ;;
        ascii.oct) ascii_to_oct "$input" ;;
        ascii.base32) echo -n "$input" | base32 ;;
        ascii.base64) echo -n "$input" | base64 ;;
        ascii.unicode) ascii_to_unicode "$input" ;;
        ascii.url) echo -n "$input" | xxd -p | sed 's/../%&/g' ;;
        ascii.rot13) echo "$input" | tr 'A-Za-z' 'N-ZA-Mn-za-m' ;;
        
        # UTF Encoders (ASCII -> Hex Rep)
        ascii.utf8) echo -n "$input" | text_to_encoded_hex "utf-8" ;;
        ascii.utf16) echo -n "$input" | text_to_encoded_hex "utf-16" ;;
        ascii.utf32) echo -n "$input" | text_to_encoded_hex "utf-32" ;;

        # UTF Decoders (Hex Rep -> ASCII)
        utf8.ascii) encoded_hex_to_text "utf-8" "$cleaned" ;;
        utf16.ascii) encoded_hex_to_text "utf-16" "$cleaned" ;;
        utf32.ascii) encoded_hex_to_text "utf-32" "$cleaned" ;;
        
        # Hex Conversions
        hex.ascii) hex_to_ascii "$cleaned" ;;
        hex.hex) echo "$cleaned" ;;
        hex.bin) python3 -c "import sys; print(bin(int(sys.argv[1], 16))[2:], end='')" "$cleaned" 2>/dev/null ;;
        hex.dec) hex_to_dec "$cleaned" ;;
        hex.oct) python3 -c "import sys; print(oct(int(sys.argv[1], 16))[2:], end='')" "$cleaned" 2>/dev/null ;;
        hex.base32) hex_to_ascii "$cleaned" | base32 ;;
        hex.base64) hex_to_ascii "$cleaned" | base64 ;;
        hex.unicode) hex_to_ascii "$cleaned" | ascii_to_unicode ;;
        hex.url) echo "$cleaned" | sed 's/../%&/g' ;;
        
        # UTF Encoders (from Hex)
        hex.utf8) hex_to_ascii "$cleaned" | text_to_encoded_hex "utf-8" ;;
        hex.utf16) hex_to_ascii "$cleaned" | text_to_encoded_hex "utf-16" ;;
        hex.utf32) hex_to_ascii "$cleaned" | text_to_encoded_hex "utf-32" ;;
        
        # ROT13 (from Hex)
        hex.rot13) hex_to_ascii "$cleaned" | tr 'A-Za-z' 'N-ZA-Mn-za-m' ;;
        
        # Binary Conversions
        bin.ascii) bin_to_ascii "$cleaned" ;;
        bin.hex) python3 -c "import sys; print(hex(int(sys.argv[1], 2))[2:], end='')" "${cleaned// /}" 2>/dev/null ;;
        bin.bin) echo "$cleaned" ;;
        bin.dec) bin_to_dec "$cleaned" ;;
        bin.oct) python3 -c "import sys; print(oct(int(sys.argv[1], 2))[2:], end='')" "${cleaned// /}" 2>/dev/null ;;
        bin.base32) bin_to_ascii "$cleaned" | base32 ;;
        bin.base64) bin_to_ascii "$cleaned" | base64 ;;
        bin.unicode) bin_to_ascii "$cleaned" | ascii_to_unicode ;;
        bin.url) bin_to_hex "$cleaned" | sed 's/../%&/g' ;;
        
        # Decimal Conversions
        dec.ascii) dec_to_ascii "$cleaned" ;;
        dec.hex) dec_to_hex "$cleaned" ;;
        dec.bin) dec_to_bin "$cleaned" ;;
        dec.dec) echo "$cleaned" ;;
        dec.oct) 
            if [[ "$cleaned" =~ " " ]]; then
                for num in $cleaned; do printf "%03o " "$num"; done | sed 's/ $//'
            else
                python3 -c "import sys; print(oct(int(sys.argv[1]))[2:], end='')" "$cleaned" 2>/dev/null
            fi
            ;;
        dec.base32) dec_to_ascii "$cleaned" | base32 ;;
        dec.base64) dec_to_ascii "$cleaned" | base64 ;;
        dec.unicode) dec_to_ascii "$cleaned" | ascii_to_unicode ;;
        dec.url) for num in $cleaned; do printf "%%%02x" "$num"; done ;;
        
        # Octal Conversions
        oct.ascii) oct_to_ascii "$cleaned" ;;
        oct.hex) python3 -c "import sys; print(hex(int(sys.argv[1], 8))[2:], end='')" "${cleaned// /}" 2>/dev/null ;;
        oct.bin) oct_to_bin "$cleaned" ;;
        oct.dec) python3 -c "import sys; print(int(sys.argv[1], 8), end='')" "${cleaned// /}" 2>/dev/null ;;
        oct.oct) echo "$cleaned" ;;
        oct.base32) oct_to_ascii "$cleaned" | base32 ;;
        oct.base64) oct_to_ascii "$cleaned" | base64 ;;
        oct.unicode) oct_to_ascii "$cleaned" | ascii_to_unicode ;;
        oct.url) for num in $cleaned; do printf "%%%02x" "0$num"; done ;;
        
        # Base32 Conversions
        base32.ascii) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); print(base64.b32decode(b + '=' * (8 - len(b) % 8), casefold=True).decode(errors='ignore'), end='')" 2>/dev/null ;;
        base32.hex) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); print(base64.b32decode(b + '=' * (8 - len(b) % 8), casefold=True).hex(), end='')" 2>/dev/null ;;
        base32.bin) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b32decode(b + '=' * (8 - len(b) % 8), casefold=True); print(''.join(format(x, '08b') for x in d), end='')" 2>/dev/null ;;
        base32.dec) 
            echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b32decode(b + '=' * (8 - len(b) % 8), casefold=True); print(' '.join(str(x) for x in d), end='')" 2>/dev/null
            ;;
        base32.oct) 
            echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b32decode(b + '=' * (8 - len(b) % 8), casefold=True); print(' '.join(format(x, '03o') for x in d), end='')" 2>/dev/null
            ;;
        base32.base64) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b32decode(b + '=' * (8 - len(b) % 8), casefold=True); print(base64.b64encode(d).decode(), end='')" 2>/dev/null ;;
        base32.unicode) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b32decode(b + '=' * (8 - len(b) % 8), casefold=True); print(' '.join([f'U+{x:04X}' for x in d]), end='')" 2>/dev/null ;;
        base32.url) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b32decode(b + '=' * (8 - len(b) % 8), casefold=True); print(''.join(['%' + format(x, '02x') for x in d]), end='')" 2>/dev/null ;;
        base32.base32) echo -n "$input" | python3 -c "import sys, base64; print(base64.b32encode(sys.stdin.read().strip().encode()).decode(), end='')" 2>/dev/null ;;

        # Base64 Conversions
        base64.ascii) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); print(base64.b64decode(b + '=' * (4 - len(b) % 4)).decode(errors='ignore'), end='')" 2>/dev/null ;;
        base64.hex) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); print(base64.b64decode(b + '=' * (4 - len(b) % 4)).hex(), end='')" 2>/dev/null ;;
        base64.bin) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b64decode(b + '=' * (4 - len(b) % 4)); print(''.join(format(x, '08b') for x in d), end='')" 2>/dev/null ;;
        base64.dec) 
            echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b64decode(b + '=' * (4 - len(b) % 4)); print(' '.join(str(x) for x in d), end='')" 2>/dev/null
            ;;
        base64.oct) 
            echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b64decode(b + '=' * (4 - len(b) % 4)); print(' '.join(format(x, '03o') for x in d), end='')" 2>/dev/null
            ;;
        base64.base32) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b64decode(b + '=' * (4 - len(b) % 4)); print(base64.b32encode(d).decode(), end='')" 2>/dev/null ;;
        base64.unicode) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b64decode(b + '=' * (4 - len(b) % 4)); print(' '.join([f'U+{x:04X}' for x in d]), end='')" 2>/dev/null ;;
        base64.url) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); d = base64.b64decode(b + '=' * (4 - len(b) % 4)); print(''.join(['%' + format(x, '02x') for x in d]), end='')" 2>/dev/null ;;
        base64.base64) echo -n "$input" | base64 | tr -d '\n' ;;
        
        # URL Conversions
        url.ascii) printf "%b" "$cleaned" ;;
        url.hex) printf "%b" "$cleaned" | xxd -p ;;
        url.bin) printf "%b" "$cleaned" | xxd -b -c 256 | sed 's/^.*: //; s/  .*//' | tr -d ' \n' ;;
        url.dec) 
            hexs=$(printf "%b" "$cleaned" | xxd -p | sed 's/../& /g')
            for hex in $hexs; do printf "%d " "0x$hex"; done | sed 's/ $//' 
            ;;
        url.oct) 
            hexs=$(printf "%b" "$cleaned" | xxd -p | sed 's/../& /g')
            for hex in $hexs; do printf "%03o " "0x$hex"; done | sed 's/ $//' 
            ;;
        url.base32) printf "%b" "$cleaned" | base32 ;;
        url.base64) printf "%b" "$cleaned" | base64 ;;
        url.unicode) printf "%b" "$cleaned" | ascii_to_unicode ;;
        url.url) echo "$input" ;;
        
        # Unicode Conversions
        unicode.ascii) unicode_to_ascii "$cleaned" ;;
        unicode.hex) unicode_to_ascii "$cleaned" | ascii_to_hex ;;
        unicode.bin) unicode_to_ascii "$cleaned" | ascii_to_bin ;;
        unicode.dec) unicode_to_ascii "$cleaned" | ascii_to_dec ;;
        unicode.oct) unicode_to_ascii "$cleaned" | ascii_to_oct ;;
        unicode.base32) unicode_to_ascii "$cleaned" | base32 ;;
        unicode.base64) unicode_to_ascii "$cleaned" | base64 ;;
        unicode.url) unicode_to_ascii "$cleaned" | xxd -p | sed 's/../%&/g' ;;
        # Rotation Conversions (Generic)
        *.rot)
            for i in $(seq 0 25); do
                printf "ROT-%02d: %s\n" "$i" "$(perform_rot "$input" "$i")"
            done
            ;;
        *.rot[0-9]|*.rot1[0-9]|*.rot2[0-5])
            shift_val=$(echo "$to" | sed 's/rot//')
            perform_rot "$input" "$shift_val"
            ;;
        
        # Universal Decoder Mapping
        ascii.decoder) echo "$input" ;;
        hex.decoder) hex_to_ascii "$cleaned" ;;
        bin.decoder) bin_to_ascii "$cleaned" ;;
        dec.decoder) dec_to_ascii "$cleaned" ;;
        oct.decoder) oct_to_ascii "$cleaned" ;;
        base32.decoder) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); print(base64.b32decode(b + '=' * (8 - len(b) % 8), casefold=True).decode(errors='ignore'), end='')" 2>/dev/null ;;
        base64.decoder) echo "$cleaned" | python3 -c "import sys, base64; b = sys.stdin.read().strip(); print(base64.b64decode(b + '=' * (4 - len(b) % 4)).decode(errors='ignore'), end='')" 2>/dev/null ;;
        url.decoder) printf "%b" "$cleaned" ;;
        unicode.decoder) unicode_to_ascii "$cleaned" ;;
        utf8.decoder) encoded_hex_to_text "utf-8" "$cleaned" ;;
        utf16.decoder) encoded_hex_to_text "utf-16" "$cleaned" ;;
        utf32.decoder) encoded_hex_to_text "utf-32" "$cleaned" ;;
        rot[0-9].decoder|rot1[0-9].decoder|rot2[0-5].decoder|rot13.decoder)
            # For ROT, decode is the inverse shift. For ROT13 it's symmetric.
            # We'll just use a generic 'decode to common readable' approach if possible, 
            # but for now we'll just treat it as the inverse shift (which for rot13 is rot13).
            if [[ "$from" == "rot13" ]]; then
                echo "$input" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
            else
                shift_val=$(echo "$from" | sed 's/rot//')
                inv_shift=$(( 26 - shift_val ))
                perform_rot "$input" "$inv_shift"
            fi
            ;;
        
        rot13.ascii) echo "$input" | tr 'A-Za-z' 'N-ZA-Mn-za-m' ;;
        rot13.rot13) echo -n "$input" | tr 'A-Za-z' 'N-ZA-Mn-za-m' | tr 'A-Za-z' 'N-ZA-Mn-za-m' ;;
        
        rot13.decoder) echo "$input" | tr 'A-Za-z' 'N-ZA-Mn-za-m' ;;
        ascii.md5) hash_string "$input" "md5" ;;
        ascii.sha1) hash_string "$input" "sha1" ;;
        ascii.sha256) hash_string "$input" "sha256" ;;
        ascii.sha384) hash_string "$input" "sha384" ;;
        ascii.sha512) hash_string "$input" "sha512" ;;
        ascii.crc32) hash_string "$input" "crc32" ;;

        # Hashes (from Hex Interpretation)
        hex.md5) hash_hex "$cleaned" "md5" ;;
        hex.sha1) hash_hex "$cleaned" "sha1" ;;
        hex.sha256) hash_hex "$cleaned" "sha256" ;;
        hex.sha384) hash_hex "$cleaned" "sha384" ;;
        hex.sha512) hash_hex "$cleaned" "sha512" ;;
        hex.crc32) hash_hex "$cleaned" "crc32" ;;
        
        *) 
            # PIVOT LOGIC: If explicit conversion not defined, try pivoting through ASCII
            # Condition: From != ascii AND To != ascii
            if [ "$from" != "ascii" ] && [ "$to" != "ascii" ]; then
                # 1. Convert From -> Ascii
                local ascii_temp
                { ascii_temp=$(perform_conversion "$input" "$from" "ascii"); } 2>/dev/null
                if [ $? -eq 0 ] && [ -n "$ascii_temp" ]; then
                     # 2. Convert Ascii -> To
                     perform_conversion "$ascii_temp" "ascii" "$to"
                     return $?
                fi
            fi
            return 1 
            ;;
    esac
}

# Main conversion router
convert() {
    local input="$1"
    local from="$2"
    local to="$3"
    
    from=$(normalize_format "$from")
    to=$(normalize_format "$to")
    
    # Clean input based on from format
    local cleaned=$(clean_input "$input" "$from")
    
    # Handle bulk options
    if [ "$to" == "all" ] || [ "$to" == "al" ]; then
        local src_id=$(get_section_id "$from")
        local src_name=$(get_section_name "$src_id")

        print_section_header "$from" "$input" "$(echo "$to" | tr '[:lower:]' '[:upper:]')" "$src_name"
        
        if [ "$to" == "all" ]; then
            print_section_1 "$input" "$from"
            echo ""
            print_section_2 "$input" "$from"
            echo ""
            print_section_3 "$input" "$from"
        else
            # Only current category
            case "$src_id" in
                1) print_section_1 "$input" "$from" ;;
                2) print_section_2 "$input" "$from" ;;
                3) print_section_3 "$input" "$from" ;;
            esac
        fi
        
        return 0
    fi

    # Handle Standard/Single Conversion
    if [[ "$to" =~ ^(ascii|unicode|utf8|utf16|utf32|hex|bin|dec|oct|md5|sha1|sha256|sha384|sha512|crc32|decoder|base64|base32|url|rot.*)$ ]]; then
        local result=$(perform_conversion "$input" "$from" "$to")
        if [ $? -eq 0 ]; then
            echo -e "${PURPLE}┌── Converting: ${CYAN}$from${NC} ${PURPLE}→${NC} ${CYAN}$to${NC} ${YELLOW}(Interpreted)${NC}"
            echo -e "${PURPLE}│${NC}  ${CYAN}Input  ${NC} : ${YELLOW}$input${NC}"
            echo -e "${PURPLE}└─${NC} ${CYAN}Output ${NC} : ${BOLD}${GREEN}$result${NC}"
            return 0
        fi
    else
        # DIRECT (Treat input as literal string)
        # We pivot through 'ascii' to use our standard transformation functions
        local result=$(perform_conversion "$input" "ascii" "$to")
        if [ $? -eq 0 ]; then
            echo -e "${PURPLE}┌── Converting: ${CYAN}$from${NC} ${PURPLE}→${NC} ${CYAN}$to${NC} ${YELLOW}(Direct)${NC}"
            echo -e "${PURPLE}│${NC}  ${CYAN}Input  ${NC} : ${YELLOW}$input${NC}"
            echo -e "${PURPLE}└─${NC} ${CYAN}Output ${NC} : ${BOLD}${GREEN}$result${NC}"
            return 0
        fi
    fi
     
    echo -e "${RED}Unsupported conversion: $from → $to${NC}"
    echo -e "${YELLOW}Supported formats:${NC}"
    echo "  hex, ascii, bin, dec, oct, base32, base64, url, unicode, rot13"
    echo "  Encoders: utf8, utf16, utf32"
    echo "  Hashes: md5, sha1, sha256, sha384, sha512, crc32"
    return 1
}

# Show banner
show_banner() {
    echo -e " "
    echo -e "  ${PURPLE}      *           .                    *          .         ${NC}"
    echo -e "  ${PURPLE}           .              .           .            *    ${NC}"
    echo -e "  ${BOLD}${PURPLE}        ██████╗ ██████╗ ██╗███████╗███╗   ███╗${NC}"
    echo -e "  ${BOLD}${PURPLE}        ██╔══██╗██╔══██╗██║██╔════╝████╗ ████║${NC}"
    echo -e "  ${BOLD}${PURPLE}        ██████╔╝██████╔╝██║███████╗██╔████╔██║${NC}"
    echo -e "  ${BOLD}${PURPLE}        ██╔═══╝ ██╔══██╗██║╚════██║██║╚██╔╝██║${NC}"
    echo -e "  ${BOLD}${PURPLE}        ██║     ██║  ██║██║███████║██║ ╚═╝ ██║${NC}"
    echo -e "  ${BOLD}${PURPLE}        ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝     ╚═╝${NC}"
    echo -e "  ${PURPLE}             .        .         .        .         *    ${NC}"
    echo -e " "
    echo -e "                ${BOLD}${PURPLE}─ Convert Your Data to Any Format ─${NC}"
    echo -e "    ${PURPLE}─────────────────────────────────────────────────────────────────${NC}"
    echo ""
}

# Show help
show_help() {
    echo -e "${CYAN}Usage:${NC}"
    echo "  $0 <input>                   Auto-detect format & show category list (al)"
    echo "  $0 <input> <from> <to>       Standard conversion (e.g., ascii to hex)"
    echo "  $0 <input> <from> all        Show EVERYTHING from all categories"
    echo "  $0 <input> <from> al         Show EVERYTHING from the source's category only"
    echo "  $0 <input> <from> decoder    Universal decode to plaintext"
    echo ""
    echo -e "${CYAN}Bulk Commands:${NC}"
    printf "  ${YELLOW}%-12s${NC} %s\n" "all"         "Generates a full report across Numbers, Transfers, and Hashes."
    printf "  ${YELLOW}%-12s${NC} %s\n" "al"          "Generates a focused report for only the relevant category."
    printf "  ${YELLOW}%-12s${NC} %s\n" "decoder"     "Interprets input into the original plaintext message."
    echo ""
    echo -e "${CYAN}Numeric Spacing Rule (Section 1):${NC}"
    echo -e "  ${WHITE}Concatenated:${NC}  '123456789' is treated as one large number."
    echo -e "  ${WHITE}Space-Sep:${NC}    '72 101 108' is treated as a sequence of ASCII bytes (H e l)."
    echo ""
    echo -e "${CYAN}Formats:${NC}"
    printf "  ${YELLOW}%-12s${NC} %s\n" "Section 1:"   "hex, bin, dec, oct, ascii, unicode, utf8/16/32"
    printf "  ${YELLOW}%-12s${NC} %s\n" "Section 2:"   "base64, base32, url, rot1-25"
    printf "  ${YELLOW}%-12s${NC} %s\n" "Section 3:"   "md5, sha1, sha256, sha512, crc32"
    echo ""
    echo -e "${CYAN}Examples:${NC}"
    echo "  $0 \"SGVsbG8=\" all            (Detect B64 and show all sections)"
    echo "  $0 \"SGVsbG8=\" b64 decoder     (Extract 'Hello' from Base64)"
    echo "  $0 \"U+0041\" al               (Detect Unicode and show Section 1)"
    echo "  $0 \"41 42 43\" hex al          (Treat as multi-byte ASCII: A B C)"
    echo "  $0 \"123456\" dec al            (Treat as single large numeric value)"
    echo "  $0 \"Hello\" rot13             (Quick ROT13 cipher)"
    echo ""
}

# Main
check_dependencies
show_banner
if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

# Auto-detect format if only input given

# Helper to detect format
detect_format() {
    local input="$1"
    
    # URL encoded (distinctive %)
    if [[ "$input" =~ %[0-9a-fA-F][0-9a-fA-F] ]]; then
        echo "url"
    # Unicode (U+...)
    elif [[ "$input" =~ U\+[0-9a-fA-F]+ ]]; then
        echo "unicode"
    # Hex with 0x prefix
    elif [[ "$input" =~ ^0x[0-9a-fA-F]+$ ]]; then
        echo "hex"
    # Binary (0 and 1 only)
    elif [[ "$input" =~ ^[01]+$ ]] && [ ${#input} -gt 1 ]; then
        echo "bin"
    # Decimal (0-9 only)
    elif [[ "$input" =~ ^[0-9\ ]+$ ]]; then
        echo "dec"
    # Hex (0-9, a-f) - Must look like hex (even length or long)
    elif [[ "$input" =~ ^[0-9a-fA-F\ ]+$ ]]; then
        # If it's short and contains letters, it's likely ASCII (unless even length like 'AF')
        local clean=$(echo "$input" | tr -d ' ')
        if [ ${#clean} -eq 1 ] && [[ "$clean" =~ [a-fA-F] ]]; then
            echo "ascii"
        elif [ $(( ${#clean} % 2 )) -eq 0 ] || [[ "$input" =~ ^[0-9]+$ ]]; then
            echo "hex"
        else
            echo "ascii"
        fi
    # Base32 (A-Z, 2-7)
    elif [[ "$input" =~ ^[A-Z2-7\ ]+={0,6}$ ]] && ([ ${#input} -ge 8 ] || [[ "$input" =~ [0-9=] ]]); then
        echo "base32"
    # Base64 - Look for padding or specific character spectrum
    elif [[ "$input" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] && ([[ "$input" =~ [+/=] ]] || [ ${#input} -gt 12 ]); then
        echo "base64"
    else
        echo "ascii"
    fi
}


if [ $# -eq 1 ]; then
    input="$1"
    fmt=$(detect_format "$input")
    echo -e "${YELLOW}Auto-detected format: $fmt${NC}"
    
    # Use 'al' target for nice categorized view
    convert "$input" "$fmt" "al"
    exit 0
fi

# Handle 2 arguments: ./conv.sh <input> <to>
if [ $# -eq 2 ]; then
    input="$1"
    target=$(normalize_format "$2")
    
    # Auto-detect input format
    detected=$(detect_format "$input")
    echo -e "${YELLOW}Auto-detected input format: $detected${NC}"

    # Check if target is "all" or "al"
    if [ "$target" == "all" ] || [ "$target" == "al" ]; then
        convert "$input" "$detected" "$target"
        exit 0
    fi

    # Check if target is a hash
    if [[ "$target" =~ ^(md5|sha1|sha256|sha384|sha512|crc32)$ ]]; then
        echo -e "${CYAN}Hashing: '$input' ($detected) → $target${NC}"
        res=$(hash_string "$input" "$target")
        echo -e "${GREEN}Output: $res${NC}"
        echo ""
        exit 0
    fi
     
    # For any other target (e.g. rot, decoder, etc.)
    convert "$input" "$detected" "$target"
    exit 0
fi

# Full conversion
if [ $# -eq 3 ]; then
    # Special Check: If target is hash, treat it as hashing only if from is ascii or compatible
    # Actually, keep strictly to the logic: convert <input> <from> <to>
    # If 'to' is a hash, we pass it to convert(), which handles it in the default case if not matched
    
    convert "$1" "$2" "$3"
    exit 0
fi

echo -e "${RED}Error: Invalid number of arguments${NC}"
show_help
exit 1
