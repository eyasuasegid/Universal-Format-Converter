#!/bin/bash
# Complete Universal Converter - ALL conversions supported

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Function to normalize format names
normalize_format() {
    case "$1" in
        hex|hexadecimal|h) echo "hex" ;;
        ascii|text|a) echo "ascii" ;;
        bin|binary|b) echo "bin" ;;
        dec|decimal|d) echo "dec" ;;
        oct|octal|o) echo "oct" ;;
        base64|b64) echo "base64" ;;
        url|percent) echo "url" ;;
        rot13|rot) echo "rot13" ;;
        *) echo "$1" ;;
    esac
}

# Function to clean input
clean_input() {
    local input="$1"
    local format="$2"
    
    case "$format" in
        hex)
            echo "$input" | sed 's/0x//g; s/[^0-9a-fA-F]//g' | tr '[:upper:]' '[:lower:]'
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
        base64)
            echo "$input" | tr -d ' \n\r='
            ;;
        url)
            echo "$input" | sed 's/%/\\x/g'
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
    echo -n "$1" | xxd -p | tr -d '\n'
}

bin_to_ascii() {
    local hex=$(bin_to_hex "$1")
    hex_to_ascii "$hex"
}

# NEW: Optimized ascii_to_bin that removes unnecessary leading zeros
ascii_to_bin() {
    echo -n "$1" | xxd -b -c 256 | sed 's/^.*: //; s/  .*//' | tr -d ' \n'
}

dec_to_ascii() {
    local hex=$(dec_to_hex "$1")
    hex_to_ascii "$hex"
}

ascii_to_dec() {
    echo -n "$1" | xxd -p | sed 's/../& /g' | tr ' ' '\n' | while read hex; do
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
    for hex in $(echo -n "$1" | xxd -p | sed 's/../& /g'); do
        printf "%03o " "0x$hex"
    done | sed 's/ $//'
}

oct_to_bin() {
    local hex=$(for num in $1; do printf "%02x" "0$num"; done)
    hex_to_bin "$hex"
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
    for num in $1; do
        printf "%02x" "$num"
    done
}

hex_to_dec() {
    local hex="$1"
    if [ $(( ${#hex} % 2 )) -eq 1 ]; then
        hex="0$hex"
    fi
    for ((i=0; i<${#hex}; i+=2)); do
        printf "%d " "0x${hex:i:2}"
    done | sed 's/ $//'
}

# FIXED: dec_to_bin - remove leading zeros
dec_to_bin() {
    local hex=$(dec_to_hex "$1")
    hex_to_bin "$hex"
}

# FIXED: bin_to_dec with dynamic padding
bin_to_dec() {
    local bin="$1"
    # Remove spaces
    bin=$(echo "$bin" | tr -d ' ')
    # Pad to complete bytes if needed
    local len=${#bin}
    if [ $((len % 8)) -ne 0 ]; then
        padding=$((8 - (len % 8)))
        bin=$(printf "%0${padding}d%s" 0 "$bin")
    fi
    # Convert each byte to decimal
    for ((i=0; i<${#bin}; i+=8)); do
        byte="${bin:i:8}"
        printf "%d " $((2#$byte))
    done | sed 's/ $//'
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
    
    echo -e "${CYAN}Converting: $from → $to${NC}"
    echo -e "${YELLOW}Input: $input${NC}"
    echo -e "${BLUE}Cleaned: $cleaned${NC}"
    echo -e "${GREEN}Output: ${NC}"
    
    case "$from.$to" in
        # ASCII Conversions
        ascii.ascii) echo "$input" ;;
        ascii.hex) ascii_to_hex "$input" ;;
        ascii.bin) ascii_to_bin "$input" ;;
        ascii.dec) ascii_to_dec "$input" ;;
        ascii.oct) ascii_to_oct "$input" ;;
        ascii.base64) echo -n "$input" | base64 ;;
        ascii.url) echo -n "$input" | xxd -p | sed 's/../%&/g' ;;
        ascii.rot13) echo "$input" | tr 'A-Za-z' 'N-ZA-Mn-za-m' ;;
        
        # Hex Conversions
        hex.ascii) hex_to_ascii "$cleaned" ;;
        hex.hex) echo "$cleaned" ;;
        hex.bin) hex_to_bin "$cleaned" ;;
        hex.dec) hex_to_dec "$cleaned" ;;
        hex.oct) 
            vals=$(hex_to_dec "$cleaned")
            for num in $vals; do printf "%03o " "$num"; done | sed 's/ $//' 
            ;;
        hex.base64) hex_to_ascii "$cleaned" | base64 ;;
        hex.url) hex_to_ascii "$cleaned" | xxd -p | sed 's/../%&/g' ;;
        
        # Binary Conversions
        bin.ascii) bin_to_ascii "$cleaned" ;;
        bin.hex) bin_to_hex "$cleaned" ;;
        bin.bin) echo "$cleaned" ;;
        bin.dec) bin_to_dec "$cleaned" ;;
        bin.oct) 
            vals=$(bin_to_dec "$cleaned")
            for num in $vals; do printf "%03o " "$num"; done | sed 's/ $//' 
            ;;
        bin.base64) bin_to_ascii "$cleaned" | base64 ;;
        bin.url) bin_to_ascii "$cleaned" | xxd -p | sed 's/../%&/g' ;;
        
        # Decimal Conversions
        dec.ascii) dec_to_ascii "$cleaned" ;;
        dec.hex) dec_to_hex "$cleaned" ;;
        dec.bin) dec_to_bin "$cleaned" ;;
        dec.dec) echo "$cleaned" ;;
        dec.oct) for num in $cleaned; do printf "%03o " "$num"; done | sed 's/ $//' ;;
        dec.base64) dec_to_ascii "$cleaned" | base64 ;;
        dec.url) dec_to_ascii "$cleaned" | xxd -p | sed 's/../%&/g' ;;
        
        # Octal Conversions
        oct.ascii) oct_to_ascii "$cleaned" ;;
        oct.hex) for num in $cleaned; do printf "%02x" "0$num"; done ;;
        oct.bin) oct_to_bin "$cleaned" ;;
        oct.dec) for num in $cleaned; do printf "%d " "0$num"; done | sed 's/ $//' ;;
        oct.oct) echo "$cleaned" ;;
        oct.base64) oct_to_ascii "$cleaned" | base64 ;;
        oct.url) oct_to_ascii "$cleaned" | xxd -p | sed 's/../%&/g' ;;
        
        # Base64 Conversions
        base64.ascii) echo "$cleaned" | base64 -d 2>/dev/null ;;
        base64.hex) echo "$cleaned" | base64 -d 2>/dev/null | xxd -p ;;
        base64.bin) echo "$cleaned" | base64 -d 2>/dev/null | xxd -b -c 256 | sed 's/^.*: //; s/  .*//' | tr -d ' \n' ;;
        base64.dec) 
            hexs=$(echo "$cleaned" | base64 -d 2>/dev/null | xxd -p | sed 's/../& /g')
            for hex in $hexs; do printf "%d " "0x$hex"; done | sed 's/ $//' 
            ;;
        base64.oct) 
            hexs=$(echo "$cleaned" | base64 -d 2>/dev/null | xxd -p | sed 's/../& /g')
            for hex in $hexs; do printf "%03o " "0x$hex"; done | sed 's/ $//' 
            ;;
        base64.url) echo "$cleaned" | base64 -d 2>/dev/null | xxd -p | sed 's/../%&/g' ;;
        base64.base64) echo "$cleaned" ;;
        
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
        url.base64) printf "%b" "$cleaned" | base64 ;;
        url.url) echo "$input" ;;
        
        # ROT13
        rot13.ascii) echo "$input" | tr 'A-Za-z' 'N-ZA-Mn-za-m' ;;
        rot13.rot13) echo "$input" ;;
        
        *) 
            echo -e "${RED}Unsupported conversion: $from → $to${NC}"
            echo -e "${YELLOW}Supported formats:${NC}"
            echo "  hex, ascii, bin, dec, oct, base64, url, rot13"
            return 1
            ;;
    esac
    echo ""
}

# Show help
show_help() {
    echo -e "${GREEN}============================================${NC}"
    echo -e "${BLUE}Universal Converter${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
    echo -e "${CYAN}Usage:${NC}"
    echo "  $0 <input> <from> <to>"
    echo "  $0 <input>                   (auto-detect to ascii)"
    echo ""
    echo -e "${CYAN}Formats (short names):${NC}"
    echo "  hex (h), ascii (a), bin (b), dec (d)"
    echo "  oct (o), base64 (b64), url, rot13"
    echo ""
    echo -e "${CYAN}Examples:${NC}"
    echo "  $0 7069636f hex ascii"
    echo "  $0 101010 bin hex"
    echo "  $0 42 dec bin"
    echo "  $0 160 151 oct hex"
    echo "  $0 picoCTF ascii bin"
    echo "  $0 0x70 hex ascii"
    echo ""

}

# Main
if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

# Auto-detect format if only input given

if [ $# -eq 1 ]; then
    echo -e "${YELLOW}Auto-detecting format...${NC}"
    input="$1"
    
    # URL encoded (distinctive %)
    if [[ "$input" =~ %[0-9a-fA-F][0-9a-fA-F] ]]; then
        convert "$input" url ascii
        
    # Binary (0 and 1 only)
    elif [[ "$input" =~ ^[01\ ]+$ ]]; then
        convert "$input" bin ascii
        
    # Decimal (0-9 only)
    elif [[ "$input" =~ ^[0-9\ ]+$ ]]; then
        convert "$input" dec ascii
        
    # Hex (0-9, a-f) - Checked AFTER binary/decimal to avoid greedy matches on '10', '100'
    elif [[ "$input" =~ ^[0-9a-fA-F\ ]+$ ]] || [[ "$input" =~ ^0x[0-9a-fA-F]+$ ]]; then
        convert "$input" hex ascii
        
    # Base64
    elif [[ "$input" =~ ^[A-Za-z0-9+/]+={0,2}$ ]]; then
        convert "$input" base64 ascii
        
    # Fallback
    else
        echo -e "${YELLOW}Assuming ASCII text. Conversions:${NC}"
        echo "  hex:    $(convert "$input" ascii hex 2>/dev/null)"
        echo "  binary: $(convert "$input" ascii bin 2>/dev/null)"
        echo "  decimal: $(convert "$input" ascii dec 2>/dev/null)"
        echo "  octal:  $(convert "$input" ascii oct 2>/dev/null)"
        echo "  base64: $(convert "$input" ascii base64 2>/dev/null)"
        echo "  URL:    $(convert "$input" ascii url 2>/dev/null)"
    fi
    exit 0
fi

# Full conversion
if [ $# -eq 3 ]; then
    convert "$1" "$2" "$3"
    exit 0
fi

echo -e "${RED}Error: Invalid number of arguments${NC}"
show_help
exit 1a
