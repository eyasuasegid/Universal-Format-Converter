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
    local bin="$1"
    # Ensure length is multiple of 8
    local len=${#bin}
    if [ $((len % 8)) -ne 0 ]; then
        padding=$((8 - (len % 8)))
        bin=$(printf "%0${padding}d%s" 0 "$bin")
    fi
    # Convert 8-bit chunks
    for ((i=0; i<${#bin}; i+=8)); do
        byte="${bin:i:8}"
        printf "\\x%02x" $((2#$byte)) 2>/dev/null
    done
}

ascii_to_bin() {
    echo -n "$1" | xxd -b | awk '{for(i=2;i<=NF;i++) printf "%s", $i}' | tr -d ' '
}

dec_to_ascii() {
    for num in $1; do
        printf "\\x%02x" "$num" 2>/dev/null
    done
}

ascii_to_dec() {
    echo -n "$1" | xxd -p | sed 's/../& /g' | while read hex; do
        [ -n "$hex" ] && printf "%d " "0x$hex"
    done | sed 's/ $//'
}

oct_to_ascii() {
    for num in $1; do
        printf "\\x%02x" "0$num" 2>/dev/null
    done
}

ascii_to_oct() {
    echo -n "$1" | xxd -p | sed 's/../& /g' | while read hex; do
        [ -n "$hex" ] && printf "%03o " "0x$hex"
    done | sed 's/ $//'
}

bin_to_hex() {
    local bin="$1"
    # Pad to multiple of 8
    local len=${#bin}
    if [ $((len % 8)) -ne 0 ]; then
        padding=$((8 - (len % 8)))
        bin=$(printf "%0${padding}d%s" 0 "$bin")
    fi
    # Convert each 8-bit chunk to hex
    for ((i=0; i<${#bin}; i+=8)); do
        byte="${bin:i:8}"
        printf "%02x" $((2#$byte))
    done
}

hex_to_bin() {
    local hex="$1"
    if [ $(( ${#hex} % 2 )) -eq 1 ]; then
        hex="0$hex"
    fi
    echo "$hex" | sed 's/./& /g' | tr ' ' '\n' | while read digit; do
        case "$digit" in
            0) echo -n "0000";;
            1) echo -n "0001";;
            2) echo -n "0010";;
            3) echo -n "0011";;
            4) echo -n "0100";;
            5) echo -n "0101";;
            6) echo -n "0110";;
            7) echo -n "0111";;
            8) echo -n "1000";;
            9) echo -n "1001";;
            a) echo -n "1010";;
            b) echo -n "1011";;
            c) echo -n "1100";;
            d) echo -n "1101";;
            e) echo -n "1110";;
            f) echo -n "1111";;
        esac
    done
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

dec_to_bin() {
    for num in $1; do
        printf "%08d " $(echo "obase=2; $num" | bc 2>/dev/null || echo "0")
    done | sed 's/ $//'
}

bin_to_dec() {
    local bin="$1"
    # Pad to multiple of 8
    local len=${#bin}
    if [ $((len % 8)) -ne 0 ]; then
        padding=$((8 - (len % 8)))
        bin=$(printf "%0${padding}d%s" 0 "$bin")
    fi
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
            hex_to_dec "$cleaned" | while read num; do
                printf "%03o " "$num"
            done | sed 's/ $//'
            ;;
        hex.base64) 
            hex_to_ascii "$cleaned" | base64
            ;;
        hex.url) 
            hex_to_ascii "$cleaned" | xxd -p | sed 's/../%&/g'
            ;;
        
        # Binary Conversions
        bin.ascii) bin_to_ascii "$cleaned" ;;
        bin.hex) bin_to_hex "$cleaned" ;;
        bin.bin) echo "$cleaned" ;;
        bin.dec) bin_to_dec "$cleaned" ;;
        bin.oct)
            bin_to_dec "$cleaned" | while read num; do
                printf "%03o " "$num"
            done | sed 's/ $//'
            ;;
        bin.base64) 
            bin_to_ascii "$cleaned" | base64
            ;;
        
        # Decimal Conversions
        dec.ascii) dec_to_ascii "$cleaned" ;;
        dec.hex) dec_to_hex "$cleaned" ;;
        dec.bin) dec_to_bin "$cleaned" ;;
        dec.dec) echo "$cleaned" ;;
        dec.oct)
            for num in $cleaned; do
                printf "%03o " "$num"
            done | sed 's/ $//'
            ;;
        dec.base64)
            dec_to_ascii "$cleaned" | base64
            ;;
        
        # Octal Conversions
        oct.ascii) oct_to_ascii "$cleaned" ;;
        oct.hex)
            for num in $cleaned; do
                printf "%02x" "0$num"
            done
            ;;
        oct.bin)
            for num in $cleaned; do
                printf "%08d " $(echo "obase=2; ibase=8; $num" | bc 2>/dev/null || echo "0")
            done | sed 's/ $//'
            ;;
        oct.dec)
            for num in $cleaned; do
                printf "%d " "0$num"
            done | sed 's/ $//'
            ;;
        oct.oct) echo "$cleaned" ;;
        
        # Base64 Conversions
        base64.ascii) echo "$cleaned" | base64 -d 2>/dev/null ;;
        base64.hex) echo "$cleaned" | base64 -d 2>/dev/null | xxd -p ;;
        base64.bin) echo "$cleaned" | base64 -d 2>/dev/null | xxd -b | awk '{for(i=2;i<=NF;i++) printf "%s", $i}' | tr -d ' ' ;;
        base64.dec) echo "$cleaned" | base64 -d 2>/dev/null | xxd -p | sed 's/../& /g' | while read hex; do [ -n "$hex" ] && printf "%d " "0x$hex"; done | sed 's/ $//' ;;
        base64.base64) echo "$cleaned" ;;
        
        # URL Conversions
        url.ascii) printf "%b" "$cleaned" ;;
        url.hex) printf "%b" "$cleaned" | xxd -p ;;
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
    echo -e "${BLUE}Universal Converter for CTFs${NC}"
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
    echo "  $0 01110000 bin hex"
    echo "  $0 112 105 99 dec hex"
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
    
    # Simple detection
    if [[ "$input" =~ ^[0-9a-fA-F]+$ ]]; then
        convert "$input" hex ascii
    elif [[ "$input" =~ ^[01\ ]+$ ]]; then
        convert "$input" bin ascii
    elif [[ "$input" =~ ^[0-9\ ]+$ ]]; then
        convert "$input" dec ascii
    elif [[ "$input" =~ ^[0-7\ ]+$ ]]; then
        convert "$input" oct ascii
    elif [[ "$input" =~ ^[A-Za-z0-9+/]+={0,2}$ ]]; then
        convert "$input" base64 ascii
    elif [[ "$input" =~ %[0-9a-fA-F][0-9a-fA-F] ]]; then
        convert "$input" url ascii
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
exit 1
