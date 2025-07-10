#!/bin/bash

INPUT="ipcheck.txt"
CSV_OUTPUT="enumerasi_domain_2.csv"
MAX_PARALLEL=10
PROGRESS_FILE="progress_count.txt"

BAR_WIDTH=40   # Lebar progress bar

# Daftar path rawan untuk dicek langsung
vuln_paths=(
    "/.git" "/.gitignore" "/.env" "/.svn" "/.DS_Store" "/config.php" "/wp-config.php"
    "/composer.json" "/composer.lock" "/package.json" "/package-lock.json" "/yarn.lock"
    "/admin" "/administrator" "/backup" "/db.sql" "/test.php" "/info.php" "/php.info"
    "/server-status" "/.htaccess" "/.htpasswd" "/error.log" "/access.log" "/cgi-bin/"
    "/robots.txt" "/sitemap.xml" "/README.md" "/readme.txt" "/LICENSE" "/web.config"
)

# Hitung total target (baris tidak kosong)
total_target=$(grep -cve '^\s*$' "$INPUT")
echo 0 > "$PROGRESS_FILE"

# Header CSV (ditulis sekali saja di awal)
header="Target,Open Ports,Service Info,HTTP Title"
for path in "${vuln_paths[@]}"; do
    header+=",${path} Accessible"
done
header+=",Vulnerability Summary"
echo "$header" > "$CSV_OUTPUT"

draw_progress_bar() {
    local progress=$1
    local total=$2
    local width=$3

    local percent=$(( 100 * progress / total ))
    local filled=$(( width * progress / total ))
    local empty=$(( width - filled ))

    local bar="["
    for ((i=0;i<filled;i++)); do bar+="#"; done
    for ((i=0;i<empty;i++)); do bar+="-"; done
    bar+="]"

    echo -ne "\r$bar $progress/$total ($percent%) selesai"
}

# --- Fungsi proses per target ---
process_target() {
    local target="$1"
    [[ -z "$target" ]] && return

    nmap -Pn -T4 -p 80,443 -sV --script=http-title "$target" -oN "temp_nmap_${target}.txt"

    open_ports=$(grep -E "^[0-9]+/tcp\s+open" "temp_nmap_${target}.txt" | awk -F/ '{print $1}' | paste -sd ";" -)
    service_info=$(grep -E "^[0-9]+/tcp\s+open" "temp_nmap_${target}.txt" | awk '{$1=$2=$3=""; print $0}' | sed 's/^ *//' | paste -sd ";" -)
    http_title=$(grep "http-title:" "temp_nmap_${target}.txt" | sed 's/.*http-title: //g' | paste -sd ";" -)

    path_status=()
    for path in "${vuln_paths[@]}"; do
        status="tidak"
        for port in 80 443 ; do
            if grep -q "^$port/tcp\s\+open" "temp_nmap_${target}.txt"; then
                proto="http"
                [[ $port == 443 || $port == 8443 ]] && proto="https"
                url="$proto://$target:$port$path"
                code=$(curl -k -s -o /dev/null -w "%{http_code}" "$url")
                if [[ "$code" == "200" || "$code" == "403" || "$code" == "401" ]]; then
                    status="$url ($code)"
                    break
                fi
            fi
        done
        path_status+=("$status")
    done

    vuln_summary=$(awk '/VULNERABLE:/ {print $2}' "temp_nmap_${target}.txt" | paste -sd ";" -)

    line="\"$target\",\"$open_ports\",\"$service_info\",\"$http_title\""
    for s in "${path_status[@]}"; do
        line+=",\"$s\""
    done
    line+=",\"$vuln_summary\""

    # Penulisan aman ke satu file CSV dengan flock
    {
        flock 200
        echo "$line" >> "$CSV_OUTPUT"
    } 200>>"$CSV_OUTPUT.lock"

    rm -f "temp_nmap_${target}.txt"

    # Update progress (thread-safe)
    {
        flock 201
        count=$(<"$PROGRESS_FILE")
        count=$((count+1))
        echo "$count" > "$PROGRESS_FILE"
        draw_progress_bar "$count" "$total_target" "$BAR_WIDTH"
    } 201>"$PROGRESS_FILE.lock"
}

# --- Main Loop: Jalankan MAX_PARALLEL jobs sekaligus ---
job_count=0
while read -r target; do
    [[ -z "$target" ]] && continue
    process_target "$target" &
    ((job_count++))
    if (( job_count % MAX_PARALLEL == 0 )); then
        wait
    fi
done < "$INPUT"
wait

echo -e "\n✅ Selesai. Hasil tersimpan di $CSV_OUTPUT"
rm -f "$PROGRESS_FILE" "$PROGRESS_FILE.lock"
