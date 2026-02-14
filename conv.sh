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
        unipoint|up) echo "unipoint" ;;
        rot) echo "rot" ;;
        rot13) echo "rot13" ;;
        rot[0-9]|rot1[0-9]|rot2[0-5]) echo "$1" ;;
        decoder|decode) echo "decoder" ;;
        utf8|utf-8) echo "utf8" ;;
        utf16be) echo "utf16be" ;;
        utf16le) echo "utf16le" ;;
        utf16|utf-16) echo "utf16be" ;;
        utf32be) echo "utf32be" ;;
        utf32le) echo "utf32le" ;;
        utf32|utf-32) echo "utf32be" ;;
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
        hex|bin|dec|oct|ascii|unicode|utf8|utf16be|utf16le|utf32be|utf32le) echo 1 ;;
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

    for fmt in unicode unipoint utf8 utf16be utf16le utf32be utf32le; do
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
            echo "$input" | sed 's/0x//g; s/,/ /g' | tr -cd '0-9a-fA-F ' | sed 's/  */ /g' | tr '[:upper:]' '[:lower:]' | sed 's/^ //; s/ $//'
            ;;
        bin)
            echo "$input" | tr -cd '01 ' | sed 's/  */ /g' | sed 's/^ //; s/ $//'
            ;;
        dec)
            echo "$input" | tr -cd '0-9 ' | sed 's/  */ /g' | sed 's/^ //; s/ $//'
            ;;
        oct)
            echo "$input" | tr -cd '0-7 ' | sed 's/  */ /g' | sed 's/^ //; s/ $//'
            ;;
        base32)
            echo "$input" | tr '[:lower:]' '[:upper:]' | tr -cd 'A-Z2-7 ' | sed 's/  */ /g' | sed 's/^ //; s/ $//'
            ;;
        base64)
            echo "$input" | tr -cd 'A-Za-z0-9+/= ' | sed 's/  */ /g' | sed 's/^ //; s/ $//'
            ;;
        url)
            echo -n "$input" | tr -d '\n\r'
            ;;
        unicode)
             echo "$input" | sed 's/[Uu]+//g; s/0x//g; s/,/ /g' | tr -cd '0-9a-fA-F ' | sed 's/^ //; s/ $//'
             ;;
        utf8|utf16|utf32|utf16be|utf16le|utf32be|utf32le)
             echo "$input" | tr -d ' \n\r' | sed 's/0x//g; s/[^0-9a-fA-F]//g' | tr '[:upper:]' '[:lower:]'
             ;;
        *)
            echo -n "$input"
            ;;
    esac
}

# --- MATHEMATICAL CONVERSION SUITE (Token-Aware Unicode) ---

# ASCII <=> HEX (Hex as concatenated string of code-points)
ascii_to_hex() {
    if [ -n "$1" ]; then echo -n "$1"; else cat; fi | python3 -c "
import sys
try:
    data = sys.stdin.read()
    print(''.join([f'{ord(c):x}' for c in data]), end='')
except: pass
"
}

hex_to_ascii() {
    python3 -c "
import sys
try:
    tokens = sys.stdin.read().split()
    print(''.join([chr(int(x, 16)) for x in tokens]), end='')
except: pass
" <<< "$1"
}

# UNICODE HELPERS
ascii_to_unicode() {
    if [ -n "$1" ]; then echo -n "$1"; else cat; fi | python3 -c "
import sys
chars = sys.stdin.read()
print(' '.join([f'U+{ord(c):04X}' for c in chars]), end='')
"
}

unicode_to_ascii() {
    if [ -n "$1" ]; then echo -n "$1"; else cat; fi | python3 -c "
import sys
try:
    code_points = sys.stdin.read().split()
    print(''.join([chr(int(cp.replace('U+',''), 16)) for cp in code_points]), end='')
except: pass
"
}

unipoint_to_ascii() { dec_to_ascii "$1"; }
ascii_to_unipoint() { ascii_to_dec "$1"; }

# NEW: Generic Python Encoding Utils
text_to_encoded_hex() {
    local codec="$1"
    python3 -c "
import sys
try:
    data = sys.stdin.buffer.read()
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        text = data.decode('latin-1')
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

# ASCII <=> BIN (Bin as concatenated string of code-points)
ascii_to_bin() {
    if [ -n "$1" ]; then echo -n "$1"; else cat; fi | python3 -c "
import sys
try:
    data = sys.stdin.read()
    print(''.join([bin(ord(c))[2:].zfill(8 if ord(c) < 256 else 16) for c in data]), end='')
except: pass
"
}

bin_to_ascii() {
    python3 -c "
import sys
try:
    tokens = sys.stdin.read().split()
    print(''.join([chr(int(x, 2)) for x in tokens]), end='')
except: pass
" <<< "$1"
}

# ASCII <=> DEC (Dec as space-separated code-points)
ascii_to_dec() {
    if [ -n "$1" ]; then echo -n "$1"; else cat; fi | python3 -c "
import sys
try:
    data = sys.stdin.read()
    print(' '.join([str(ord(c)) for c in data]), end='')
except: pass
"
}

dec_to_ascii() {
    python3 -c "
import sys
try:
    tokens = sys.stdin.read().split()
    print(''.join([chr(int(x)) for x in tokens]), end='')
except: pass
" <<< "$1"
}

# ASCII <=> OCT (Oct as space-separated code-points)
ascii_to_oct() {
    if [ -n "$1" ]; then echo -n "$1"; else cat; fi | python3 -c "
import sys
try:
    data = sys.stdin.read()
    print(' '.join([oct(ord(c))[2:] for c in data]), end='')
except: pass
"
}

oct_to_ascii() {
    python3 -c "import sys; print(''.join([chr(int(x, 8)) for x in sys.argv[1].split()]), end='')" "$1" 2>/dev/null
}

# CROSS-NUMERICAL (Always token-aware via Decimal intermediate)
hex_to_dec() {
    python3 -c "import sys; print(' '.join([str(int(t, 16)) for t in sys.stdin.read().split()]), end='')" <<< "$1"
}

bin_to_dec() {
    python3 -c "import sys; print(' '.join([str(int(t, 2)) for t in sys.stdin.read().split()]), end='')" <<< "$1"
}

oct_to_dec() {
    python3 -c "import sys; print(' '.join([str(int(t, 8)) for t in sys.stdin.read().split()]), end='')" <<< "$1"
}

dec_to_hex() {
    python3 -c "import sys; print(' '.join([f'{int(t):x}' for t in sys.stdin.read().split()]), end='')" <<< "$1" 2>/dev/null
}

dec_to_bin() {
    python3 -c "import sys; print(' '.join([bin(int(t))[2:].zfill(8 if int(t) < 256 else 16) for t in sys.stdin.read().split()]), end='')" <<< "$1" 2>/dev/null
}

dec_to_oct() {
    python3 -c "import sys; print(' '.join([oct(int(t))[2:] for t in sys.stdin.read().split()]), end='')" <<< "$1" 2>/dev/null
}

# UTILS
hex_to_bin() { local d=$(hex_to_dec "$1"); dec_to_bin "$d"; }
bin_to_hex() { local d=$(bin_to_dec "$1"); dec_to_hex "$d"; }




# NEW: Hashing Function
hash_string() {
    local input="$1"
    local algo="$2"
    
    _hash_one() {
        local val="$1"
        local alg="$2"
        case "$alg" in
            md5)    echo -n "$val" | md5sum | awk '{print $1}' ;;
            sha1)   echo -n "$val" | sha1sum | awk '{print $1}' ;;
            sha256) echo -n "$val" | sha256sum | awk '{print $1}' ;;
            sha384) echo -n "$val" | sha384sum | awk '{print $1}' ;;
            sha512) echo -n "$val" | sha512sum | awk '{print $1}' ;;
            crc32)  echo -n "$val" | crc32 /dev/stdin ;;
        esac
    }

    if [[ "$input" =~ " " ]]; then
        local first=1
        for token in $input; do
            [ $first -eq 0 ] && echo -n " "
            _hash_one "$token" "$algo"
            first=0
        done
    else
        _hash_one "$input" "$algo"
    fi
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
    local cleaned=$(clean_input "$input" "$from")
    
    case "$from.$to" in
        # Self-normalization
        hex.hex|bin.bin|dec.dec|oct.oct|ascii.ascii|unipoint.unipoint|unicode.unicode|base64.base64|base32.base32|url.url|utf8.utf8|utf16be.utf16be|utf16le.utf16le|utf32be.utf32be|utf32le.utf32le) echo "$cleaned" ;;
        
        # Mathematical suite redirects (Token-Aware)
        ascii.hex) ascii_to_hex "$input" ;;
        ascii.bin) ascii_to_bin "$input" ;;
        ascii.dec) ascii_to_dec "$input" ;;
        ascii.oct) ascii_to_oct "$input" ;;
        ascii.unicode) ascii_to_unicode "$input" ;;
        ascii.unipoint) ascii_to_dec "$input" ;;
        ascii.base64) 
            if [[ "$input" =~ " " ]]; then
                for t in $input; do echo -n "$t" | base64 | tr -d '\n'; echo -n " "; done | sed 's/ $//'
            else
                echo -n "$input" | base64 | tr -d '\n'
            fi ;;
        ascii.base32) 
            if [[ "$input" =~ " " ]]; then
                for t in $input; do echo -n "$t" | base32 | tr -d '\n'; echo -n " "; done | sed 's/ $//'
            else
                echo -n "$input" | base32 | tr -d '\n'
            fi ;;
        ascii.url) 
            if [[ "$input" =~ " " ]]; then
                for t in $input; do printf "%s" "$t" | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read()), end='')"; echo -n " "; done | sed 's/ $//'
            else
                printf "%s" "$input" | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read()), end='')"
            fi ;;
        ascii.rot13) perform_rot "$input" 13 ;;

        hex.ascii) hex_to_ascii "$cleaned" ;;
        hex.dec) hex_to_dec "$cleaned" ;;
        hex.bin) hex_to_bin "$cleaned" ;;
        hex.oct) local d=$(hex_to_dec "$cleaned"); dec_to_oct "$d" ;;
        
        bin.ascii) bin_to_ascii "$cleaned" ;;
        bin.dec) bin_to_dec "$cleaned" ;;
        bin.hex) bin_to_hex "$cleaned" ;;
        bin.oct) local d=$(bin_to_dec "$cleaned"); dec_to_oct "$d" ;;
        
        dec.ascii) dec_to_ascii "$cleaned" ;;
        dec.hex) dec_to_hex "$cleaned" ;;
        dec.bin) dec_to_bin "$cleaned" ;;
        dec.oct) dec_to_oct "$cleaned" ;;
        dec.unipoint) echo "$cleaned" ;;

        oct.ascii) oct_to_ascii "$cleaned" ;;
        oct.dec) oct_to_dec "$cleaned" ;;
        oct.hex) local d=$(oct_to_dec "$cleaned"); dec_to_hex "$d" ;;
        oct.bin) local d=$(oct_to_dec "$cleaned"); dec_to_bin "$d" ;;

        unipoint.ascii) dec_to_ascii "$cleaned" ;;
        unipoint.dec) echo "$cleaned" ;;
        unipoint.hex) dec_to_hex "$cleaned" ;;
        unipoint.oct) dec_to_oct "$cleaned" ;;
        unipoint.bin) dec_to_bin "$cleaned" ;;

        unicode.ascii) unicode_to_ascii "$cleaned" ;;
        unicode.dec) local a=$(unicode_to_ascii "$cleaned"); ascii_to_dec "$a" ;;
        unicode.hex) local a=$(unicode_to_ascii "$cleaned"); ascii_to_hex "$a" ;;
        unicode.unipoint) local a=$(unicode_to_ascii "$cleaned"); ascii_to_dec "$a" ;;

        # UTF Decoders
        utf8.ascii) encoded_hex_to_text "utf-8" "$cleaned" ;;
        utf16be.ascii) encoded_hex_to_text "utf-16be" "$cleaned" ;;
        utf16le.ascii) encoded_hex_to_text "utf-16le" "$cleaned" ;;
        utf32be.ascii) encoded_hex_to_text "utf-32be" "$cleaned" ;;
        utf32le.ascii) encoded_hex_to_text "utf-32le" "$cleaned" ;;

        *.utf*)
            local codec=$(echo "$to" | sed 's/.*\.\(.*\)/\1/')
            # Map to python codec names
            case "$codec" in
                utf8) codec="utf-8" ;;
                utf16) codec="utf-16be" ;;
                utf16be) codec="utf-16be" ;;
                utf16le) codec="utf-16le" ;;
                utf32) codec="utf-32be" ;;
                utf32be) codec="utf-32be" ;;
                utf32le) codec="utf-32le" ;;
            esac
            local a=$(perform_conversion "$input" "$from" "ascii")
            if [[ "$a" =~ " " ]]; then
                for t in $a; do echo -n "$t" | text_to_encoded_hex "$codec"; echo -n " "; done | sed 's/ $//'
            else
                echo -n "$a" | text_to_encoded_hex "$codec"
            fi ;;
        *.url) 
            local a=$(perform_conversion "$input" "$from" "ascii")
            if [[ "$a" =~ " " ]]; then
                for t in $a; do printf "%s" "$t" | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read()), end='')"; echo -n " "; done | sed 's/ $//'
            else
                printf "%s" "$a" | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read()), end='')"
            fi ;;

        # Transfer (Base/URL)
        base32.ascii) 
            python3 -c "
import sys, base64
try:
    tokens = sys.stdin.read().split()
    res = []
    for t in tokens:
        t += '=' * (8 - len(t) % 8)
        res.append(base64.b32decode(t, casefold=True).decode(errors='ignore'))
    print(' '.join(res), end='')
except: pass
" <<< "$cleaned" 2>/dev/null ;;
        base64.ascii) 
            python3 -c "
import sys, base64
try:
    tokens = sys.stdin.read().split()
    res = []
    for t in tokens:
        t += '=' * (4 - len(t) % 4)
        res.append(base64.b64decode(t).decode(errors='ignore'))
    print(' '.join(res), end='')
except: pass
" <<< "$cleaned" 2>/dev/null ;;
        url.ascii) 
            python3 -c "
import sys, urllib.parse
try:
    tokens = sys.stdin.read().split()
    res = [urllib.parse.unquote(t) for t in tokens]
    print(' '.join(res), end='')
except: pass
" <<< "$cleaned" 2>/dev/null ;;

        # Bulk/Decoder
        *.decoder) perform_conversion "$input" "$from" "ascii" ;;

        # Ciphers
        *.rot)
            for i in $(seq 0 25); do
                printf "ROT-%02d: %s\n" "$i" "$(perform_rot "$input" "$i")"
            done
            ;;
        *.rot13) perform_rot "$input" 13 ;;
        *.rot[0-9]|*.rot1[0-9]|*.rot2[0-5])
            shift_val=$(echo "$to" | sed 's/rot//')
            perform_rot "$input" "$shift_val"
            ;;

        # Hashes
        *.md5|*.sha1|*.sha256|*.sha384|*.sha512|*.crc32)
            algo=$(echo "$to" | sed 's/.*\.\(.*\)/\1/')
            hash_string "$(perform_conversion "$input" "$from" "ascii")" "$algo"
            ;;

        *) 
            # PIVOT LOGIC: If explicit conversion not defined, try pivoting through ASCII
            if [ "$from" != "ascii" ] && [ "$to" != "ascii" ]; then
                local a=$(perform_conversion "$input" "$from" "ascii")
                [ -n "$a" ] && perform_conversion "$a" "ascii" "$to" && return 0
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
    printf "  ${YELLOW}%-12s${NC} %s\n" "Section 1:"   "hex, bin, dec, oct, ascii, unipoint, utf8/16/32"
    printf "  ${YELLOW}%-12s${NC} %s\n" "Section 2:"   "base64, base32, url, rot1-25"
    printf "  ${YELLOW}%-12s${NC} %s\n" "Section 3:"   "md5, sha1, sha256, sha512, crc32"
    echo ""
    echo -e "${CYAN}Examples:${NC}"
    echo "  $0 \"SGVsbG8=\" all            (Detect B64 and show all sections)"
    echo "  $0 \"SGVsbG8=\" b64 decoder     (Extract 'Hello' from Base64)"
    echo "  $0 \"Eyasu\" unipoint           (Show Unicode code points for name)"
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
