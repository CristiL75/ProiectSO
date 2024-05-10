#!/bin/bash
file="$1"
if [ ! -f "$file" ]; then
    echo "Fișierul $file nu există."
    exit 1
fi
if [[ $(file -b "$file") == "ASCII text" ]]; then
    lines=$(wc -l < "$file")
    words=$(wc -w < "$file")
    size=$(du -b "$file" | cut -f1)
    non_ascii=$(grep -cP "[^\x00-\x7F]" "$file")
    keyword_count=0
    keywords=("corrupted" "dangerous" "risk" "attack" "malware" "malicious")
    for keyword in "${keywords[@]}"; do
        if grep -q -i "$keyword" "$file"; then
            keyword_count=$((keyword_count + 1))
        fi
    done
    if [[ $lines -lt 3 && $words -gt 1000 && $size -gt 2000 ]] || [ $non_ascii -gt 0 ] || [ $keyword_count -gt 0 ]; then
        echo "CORUPT"
    else
        echo "SIGUR"
    fi
else
    echo "Nu este un fișier text ASCII."
fi