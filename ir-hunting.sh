#!/bin/bash

set -o pipefail

if [ "$EUID" -ne 0 ]; then
    echo -e "\e[31m[!] Ce script doit être lancé en tant que root (sudo).\e[0m"
    exit 1
fi

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; BLU='\033[0;34m'; NC='\033[0m'
HIGH="${RED}[🔴 HIGH]${NC}"
MED="${YEL}[🟡 MEDIUM]${NC}"
LOW="${GRN}[🟢 LOW]${NC}"
INFO="${BLU}[ℹ️ INFO]${NC}"

HOSTNAME=$(hostname)
DATE=$(date +%Y-%m-%d_%H-%M-%S)
OUTPUT_FILE="Audit_Global_${HOSTNAME}_${DATE}.txt"
BASELINE_DIR="/var/lib/ir-hunter/baseline"
MODE="${1:-audit}"
PRUNE='-path /proc -o -path /sys -o -path /run -o -path /snap -o -path /var/lib/docker'

PKG_MGR=""
DISTRO_ID=""
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_ID="${ID:-unknown}"
    fi
    if command -v dpkg-query >/dev/null 2>&1; then
        PKG_MGR="dpkg"
    elif command -v rpm >/dev/null 2>&1; then
        PKG_MGR="rpm"
    fi
}
detect_distro

list_packages() {
    case "$PKG_MGR" in
        dpkg) dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null ;;
        rpm)  rpm -qa 2>/dev/null ;;
    esac
}

gather_cron() {
    for f in /etc/crontab /etc/cron.d/*; do
        [ -f "$f" ] && grep -vE '^\s*(#|$)' "$f" 2>/dev/null | sed "s|^|$f: |"
    done
    for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        [ -d "$d" ] && find "$d" -maxdepth 1 -type f 2>/dev/null
    done
    for cdir in /var/spool/cron /var/spool/cron/crontabs; do
        if [ -d "$cdir" ]; then
            for uf in "$cdir"/*; do
                [ -f "$uf" ] && grep -vE '^\s*(#|$)' "$uf" 2>/dev/null | \
                    sed "s|^|crontab($(basename "$uf")): |"
            done
        fi
    done
}

snapshot_to() {
    local dir="$1"
    mkdir -p "$dir"
    find / -xdev \( $PRUNE \) -prune -o -type f -perm -4000 -print 2>/dev/null | sort > "$dir/suid.txt"
    find / -xdev \( $PRUNE \) -prune -o -type f -perm -2000 -print 2>/dev/null | sort > "$dir/sgid.txt"
    ss -tulpnH 2>/dev/null | awk '{print $1, $5}' | sort -u > "$dir/listen.txt"
    list_packages | sort > "$dir/packages.txt"
    cut -d: -f1,3,4,6,7 /etc/passwd | sort > "$dir/users.txt"
    systemctl list-unit-files --type=service --no-pager 2>/dev/null | sort > "$dir/services.txt"
    gather_cron | sort > "$dir/cron.txt"
    find /usr/bin /usr/sbin /bin /sbin -type f 2>/dev/null -exec sha256sum {} + 2>/dev/null \
        | sort -k2 > "$dir/bin_hashes.txt"
    lsmod 2>/dev/null | sort > "$dir/modules.txt"
    find /usr/lib/modules /lib/modules -name "*.ko" 2>/dev/null | sort > "$dir/ko_files.txt"
}

do_baseline() {
    echo -e "$INFO Création de la baseline dans $BASELINE_DIR ..."
    snapshot_to "$BASELINE_DIR"
    chmod -R 600 "$BASELINE_DIR" 2>/dev/null
    echo -e "  $LOW Baseline enregistrée :"
    ls -1 "$BASELINE_DIR" | sed 's/^/       -> /'
}

compare_item() {
    local name="$1" label="$2"
    local base="$BASELINE_DIR/$name.txt"
    local cur="$TMP_SNAP/$name.txt"
    echo -e "$INFO Comparaison : $label"
    if [ ! -f "$base" ]; then
        echo -e "  $MED Pas de baseline pour '$name'. Lance d'abord : $0 baseline"
        echo ""
        return
    fi
    local added removed
    added=$(comm -13 "$base" "$cur")
    removed=$(comm -23 "$base" "$cur")
    if [ -n "$added" ]; then
        echo -e "  $HIGH AJOUTÉ depuis la baseline :"
        echo "$added" | sed 's/^/       + /'
    fi
    if [ -n "$removed" ]; then
        echo -e "  $MED SUPPRIMÉ / disparu depuis la baseline :"
        echo "$removed" | sed 's/^/       - /'
    fi
    if [ -z "$added" ] && [ -z "$removed" ]; then
        echo -e "  $LOW Identique à la baseline."
    fi
    echo ""
}

do_check() {
    echo "==============================================================="
    echo "🔍 IR-Hunter v4 — MODE CHECK (diff baseline) sur $HOSTNAME"
    echo "📅 Date : $(date)"
    echo "📄 Rapport : $OUTPUT_FILE"
    echo "==============================================================="
    echo ""
    if [ ! -d "$BASELINE_DIR" ]; then
        echo -e "$HIGH Aucune baseline trouvée. Lance d'abord : $0 baseline"
        exit 1
    fi
    TMP_SNAP=$(mktemp -d)
    trap 'rm -rf "$TMP_SNAP"' EXIT
    snapshot_to "$TMP_SNAP"
    compare_item suid       "Binaires SUID"
    compare_item sgid       "Binaires SGID"
    compare_item listen     "Ports en écoute"
    compare_item packages   "Paquets installés"
    compare_item users      "Comptes utilisateurs"
    compare_item services   "Services systemd"
    compare_item cron       "Tâches planifiées"
    compare_item bin_hashes "Intégrité des binaires (/usr/bin, /bin…)"
    compare_item modules    "Modules kernel chargés"
    compare_item ko_files   "Fichiers .ko sur disque"
    echo "==============================================================="
    echo "✅ Fin du check. Tout '+ AJOUTÉ' mérite une investigation."
    echo "==============================================================="
}

run_audit() {
echo "==============================================================="
echo "🔍 IR-Hunter v4 — audit approfondi sur $HOSTNAME ($DISTRO_ID / $PKG_MGR)"
echo "📅 Date : $(date)"
echo "📄 Rapport sauvegardé dans : $OUTPUT_FILE"
echo "==============================================================="
echo ""

echo -e "$INFO 1. Comptes UID 0, mots de passe vides, fichiers sensibles..."
for user in $(awk -F: '($3 == 0){print $1}' /etc/passwd); do
    if [ "$user" != "root" ]; then
        echo -e "  $HIGH Compte non-root avec UID 0 : $user"
    else
        echo -e "  $LOW Compte root standard détecté."
    fi
done
awk -F: '($2 == ""){print $1}' /etc/shadow 2>/dev/null | while read -r u; do
    [ -n "$u" ] && echo -e "  $HIGH Compte SANS mot de passe : $u"
done
echo -e "  $INFO Dernière modification des fichiers de comptes :"
ls -la --time-style=long-iso /etc/passwd /etc/shadow 2>/dev/null | \
    awk '{print "       -> "$6" "$7" "$8}'

echo -e "  $INFO Comptes avec shells non-standard :"
awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 != "" && $3 >= 1000 && $3 != 65534){
    print "       -> "$1" (UID="$3", shell="$7")"}' /etc/passwd

echo -e "  $INFO Comptes avec home dans des répertoires inhabituels :"
awk -F: '($6 !~ /^\/home/ && $6 != "/root" && $6 != "/var/mail" && $6 != "/nonexistent" && $3 >= 500){
    print "       -> "$1" home="$6}' /etc/passwd

echo -e "  $INFO Vérification du fichier sudoers et sudoers.d :"
ls -la --time-style=long-iso /etc/sudoers 2>/dev/null | awk '{print "       -> "$6" "$7" "$8}'
find /etc/sudoers.d -type f -mtime -7 2>/dev/null | while read -r f; do
    echo -e "  $HIGH Fichier sudoers modifié récemment (<7j) : $f"
    cat "$f" 2>/dev/null | sed 's/^/       /'
done
grep -E 'NOPASSWD|ALL.*ALL' /etc/sudoers 2>/dev/null | grep -v '^#' | while read -r line; do
    echo -e "  $MED Règle sudoers large : $line"
done
echo ""

echo -e "$INFO 2. Clés SSH (authorized_keys)..."
for home_dir in $(awk -F: '($3 >= 1000 && $3 != 65534) || $3 == 0 {print $6}' /etc/passwd); do
    if [ -f "$home_dir/.ssh/authorized_keys" ]; then
        echo -e "  $MED Fichier de clés trouvé : $home_dir/.ssh/authorized_keys"
        while read -r key; do
            [ -n "$key" ] && echo -e "       -> $key"
        done < "$home_dir/.ssh/authorized_keys"
    fi
    if [ -f "$home_dir/.ssh/authorized_keys2" ]; then
        echo -e "  $HIGH Fichier authorized_keys2 (non-standard) : $home_dir/.ssh/authorized_keys2"
        cat "$home_dir/.ssh/authorized_keys2" 2>/dev/null | sed 's/^/       /'
    fi
done
echo -e "  $INFO Clés privées SSH hors des home habituels :"
find / -xdev \( $PRUNE \) -prune -o -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" \
    2>/dev/null -print | grep -vE '^/home|^/root' | while read -r k; do
    echo -e "  $HIGH Clé privée SSH en dehors des home : $k"
done
echo ""

echo -e "$INFO 3. Tâches Cron suspectes (toutes sources)..."
gather_cron | grep -E 'wget|curl|nc |ncat|/dev/tcp|bash -i|base64|python.*-c|sh ' | \
    while read -r line; do
        echo -e "  $HIGH Commande cron suspecte : $line"
    done
for u in $(cut -d: -f1 /etc/passwd); do
    out=$(crontab -l -u "$u" 2>/dev/null | grep -vE '^\s*(#|$)')
    [ -n "$out" ] && echo -e "  $MED Crontab de '$u' :\n$(echo "$out" | sed 's/^/       /')"
done

echo -e "  $INFO Tâches AT planifiées :"
if command -v atq >/dev/null 2>&1; then
    ATQ=$(atq 2>/dev/null)
    if [ -n "$ATQ" ]; then
        echo -e "  $MED Tâches AT en attente :"
        echo "$ATQ" | sed 's/^/       /'
        echo "$ATQ" | awk '{print $1}' | while read -r jobid; do
            echo -e "  $INFO Contenu de la tâche AT $jobid :"
            at -c "$jobid" 2>/dev/null | tail -5 | sed 's/^/       /'
        done
    else
        echo -e "  $LOW Aucune tâche AT planifiée."
    fi
else
    echo -e "  $MED 'at' non disponible."
fi
echo ""

echo -e "$INFO 4. Services & timers systemd récents..."
for SYSTEMD_DIR in /etc/systemd/system /usr/lib/systemd/system /run/systemd/system; do
    [ -d "$SYSTEMD_DIR" ] || continue
    NEW_SERVICES=$(find "$SYSTEMD_DIR" -type f -name "*.service" -mtime -2 2>/dev/null)
    if [ -n "$NEW_SERVICES" ]; then
        echo -e "  $HIGH Services créés/modifiés <48h dans $SYSTEMD_DIR :"
        echo "$NEW_SERVICES" | while read -r service; do
            echo -e "       -> $service"
            grep -E 'ExecStart|ExecStop' "$service" 2>/dev/null | sed 's/^/          /'
        done
    fi
done
find /home/*/.config/systemd/user /root/.config/systemd/user -type f -name "*.service" \
    -mtime -2 2>/dev/null | while read -r s; do
        echo -e "  $HIGH Service utilisateur récent : $s"
done
echo -e "  $INFO Timers systemd actifs :"
systemctl list-timers --all --no-pager 2>/dev/null | sed 's/^/       /'
echo ""

echo -e "$INFO 5. Exécutables ELF récents dans zones temporaires..."
FOUND=0
for f in $(find /tmp /var/tmp /dev/shm -type f -mtime -7 2>/dev/null); do
    if file "$f" 2>/dev/null | grep -q 'ELF'; then
        echo -e "  $HIGH Binaire ELF en zone temporaire : $f"
        echo -e "       $(file "$f" | cut -d: -f2-)"
        ls -la "$f" 2>/dev/null | sed 's/^/       /'
        sha256sum "$f" 2>/dev/null | sed 's/^/       SHA256: /'
        FOUND=1
    fi
done
[ "$FOUND" -eq 0 ] && echo -e "  $LOW Aucun binaire ELF récent suspect dans les zones temporaires."
echo ""

echo -e "$INFO 6. Binaires SUID/SGID créés récemment..."
SUID_FILES=$(find / -xdev \( $PRUNE \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -mtime -2 -print 2>/dev/null)
if [ -n "$SUID_FILES" ]; then
    echo -e "  $HIGH Binaires SUID/SGID modifiés/créés <48h :"
    echo "$SUID_FILES" | sed 's/^/       -> /'
else
    echo -e "  $LOW Pas de binaire SUID/SGID récent suspect."
fi

echo -e "  $INFO Binaires SUID dans les home utilisateurs (toujours suspect) :"
find /home /root -type f -perm -4000 2>/dev/null | while read -r f; do
    echo -e "  $HIGH SUID dans home : $f"
done
echo ""

echo -e "$INFO 7. Détournement de bibliothèques (ld.so.preload, LD_PRELOAD, fichiers RC)..."
if [ -s /etc/ld.so.preload ]; then
    echo -e "  $HIGH /etc/ld.so.preload présent (technique de rootkit) :"
    sed 's/^/       -> /' /etc/ld.so.preload
else
    echo -e "  $LOW /etc/ld.so.preload absent ou vide."
fi

echo -e "  $INFO Recherche de LD_PRELOAD dans les environnements de processus :"
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    env_file="/proc/$pid/environ"
    if [ -r "$env_file" ]; then
        if tr '\0' '\n' < "$env_file" 2>/dev/null | grep -q 'LD_PRELOAD'; then
            cmdline=$(cat /proc/"$pid"/cmdline 2>/dev/null | tr '\0' ' ')
            preload_val=$(tr '\0' '\n' < "$env_file" 2>/dev/null | grep 'LD_PRELOAD')
            echo -e "  $HIGH LD_PRELOAD détecté — PID $pid ($cmdline) : $preload_val"
        fi
    fi
done

echo -e "  $INFO Bibliothèques partagées dans des chemins inhabituels :"
ldconfig -p 2>/dev/null | grep -vE '/usr/lib|/lib|/usr/local/lib' | grep '\.so' | while read -r line; do
    echo -e "  $MED Bibliothèque hors chemin standard : $line"
done

RC_HITS=$(grep -RsiE 'curl|wget|/dev/tcp|nc |ncat|base64 -d|eval ' \
    /etc/profile /etc/profile.d/ /etc/bash.bashrc \
    /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile 2>/dev/null)
if [ -n "$RC_HITS" ]; then
    echo -e "  $HIGH Commandes suspectes dans fichiers de démarrage shell :"
    echo "$RC_HITS" | sed 's/^/       -> /'
else
    echo -e "  $LOW Aucun motif suspect dans les fichiers RC."
fi

echo -e "  $INFO Vérification des alias shell dans les fichiers de conf :"
grep -RsiE '^\s*alias ' /root/.bashrc /root/.bash_aliases /home/*/.bashrc \
    /home/*/.bash_aliases 2>/dev/null | grep -iE 'curl|wget|nc |bash|python|perl|ruby|php' | \
    while read -r line; do
        echo -e "  $HIGH Alias suspect : $line"
    done
echo ""

echo -e "$INFO 8. Fichiers immuables (chattr +i)..."
IMMUT=$(lsattr -R /etc /usr/bin /usr/sbin /tmp /var/tmp 2>/dev/null | grep -- '----i')
if [ -n "$IMMUT" ]; then
    echo -e "  $HIGH Fichiers immuables détectés :"
    echo "$IMMUT" | sed 's/^/       -> /'
else
    echo -e "  $LOW Aucun fichier immuable inhabituel détecté."
fi
echo ""

echo -e "$INFO 9. Réseau — ports en écoute, connexions sortantes, sockets UNIX..."
echo -e "  $INFO Ports en écoute :"
ss -tulpn 2>/dev/null | sed 's/^/       /'
echo -e "  $INFO Connexions sortantes établies :"
ss -tnp state established 2>/dev/null | sed 's/^/       /'

echo -e "  $INFO Sockets UNIX inhabituelles en écoute :"
ss -xlp 2>/dev/null | grep -vE '/run|/var/run|/tmp/.X|/tmp/dbus|/tmp/ssh' | sed 's/^/       /'

for pid in $(ss -tulpnH 2>/dev/null | grep -oP 'pid=\K[0-9]+' | sort -u); do
    exe=$(ls -l /proc/"$pid"/exe 2>/dev/null | awk -F'-> ' '{print $2}')
    case "$exe" in
        *deleted*|/tmp/*|/var/tmp/*|/dev/shm/*)
            echo -e "  $HIGH Processus en écoute suspect : PID $pid -> $exe" ;;
    esac
done

echo -e "  $INFO Règles iptables actives :"
if command -v iptables >/dev/null 2>&1; then
    iptables -L -n -v 2>/dev/null | grep -vE '^Chain|^target|^$' | \
        grep -v '0     0' | sed 's/^/       /'
fi
echo ""

echo -e "$INFO 10. Processus fantômes (binaire supprimé)..."
DELETED_PROCS=$(ls -al /proc/*/exe 2>/dev/null | grep 'deleted')
if [ -n "$DELETED_PROCS" ]; then
    echo -e "  $HIGH Processus dont le binaire source a été supprimé :"
    echo "$DELETED_PROCS" | awk '{print "       -> "$9" "$10" "$11}'
else
    echo -e "  $LOW Aucun processus fantôme détecté."
fi

echo -e "  $INFO Processus avec des noms camouflés (espaces, caractères invisibles) :"
ps aux 2>/dev/null | awk '{print $1, $2, $11}' | while read -r user pid cmd; do
    if echo "$cmd" | grep -qP '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]'; then
        echo -e "  $HIGH Processus PID $pid ($user) avec caractères non-imprimables dans le nom"
    fi
done

echo -e "  $INFO Processus en cours avec capabilities élevées :"
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    cap_file="/proc/$pid/status"
    if [ -r "$cap_file" ]; then
        cap_eff=$(grep 'CapEff:' "$cap_file" 2>/dev/null | awk '{print $2}')
        if [ -n "$cap_eff" ] && [ "$cap_eff" != "0000000000000000" ]; then
            cmdline=$(cat /proc/"$pid"/cmdline 2>/dev/null | tr '\0' ' ' | head -c 60)
            echo -e "       PID $pid CapEff=$cap_eff : $cmdline"
        fi
    fi
done | head -40
echo ""

echo -e "$INFO 11. Modules kernel — chargés, récents, inconnus..."
echo -e "  $INFO Modules actuellement chargés :"
lsmod 2>/dev/null | sed 's/^/       /'

echo -e "  $INFO Modules récemment insérés (dmesg) :"
dmesg 2>/dev/null | grep -iE 'module|insmod|modprobe|loaded' | tail -20 | sed 's/^/       /'

echo -e "  $INFO Fichiers .ko présents hors des dossiers modules officiels :"
find / -xdev \( $PRUNE \) -prune -o -name "*.ko" -print 2>/dev/null | \
    grep -vE '^/lib/modules|^/usr/lib/modules' | while read -r ko; do
        echo -e "  $HIGH Module kernel hors chemin officiel : $ko"
        ls -la "$ko" 2>/dev/null | sed 's/^/       /'
done

echo -e "  $INFO Appels récents à insmod/modprobe dans les logs :"
grep -hiE 'insmod|modprobe' /var/log/syslog /var/log/messages /var/log/kern.log 2>/dev/null | \
    tail -20 | sed 's/^/       /'
echo ""

echo -e "$INFO 12. Périphériques USB / SCSI branchés (historique)..."
echo -e "  $INFO Périphériques USB détectés via dmesg :"
dmesg 2>/dev/null | grep -iE 'usb|scsi|sd[a-z]|new.*device|idVendor|idProduct|SerialNumber|Manufacturer' | \
    grep -v 'hub\|root hub\|xhci\|ehci\|ohci\|uhci' | sed 's/^/       /'

echo -e "  $INFO Journaux udev/systemd pour périphériques USB :"
journalctl -k 2>/dev/null | grep -iE 'usb|scsi|new.*attached|removed.*device' | \
    tail -30 | sed 's/^/       /'

echo -e "  $INFO Périphériques de bloc actuellement détectés :"
lsblk -o NAME,SIZE,TYPE,TRAN,VENDOR,MODEL,SERIAL 2>/dev/null | sed 's/^/       /'

echo -e "  $INFO Historique des montages (/etc/mtab, /proc/mounts) :"
cat /proc/mounts 2>/dev/null | grep -vE 'tmpfs|sysfs|proc|devpts|securityfs|cgroup|pstore|bpf|debugfs|tracefs|hugetlbfs|mqueue|fusectl|configfs' | sed 's/^/       /'

echo -e "  $INFO Logs de connexions de périphériques dans syslog :"
grep -hiE 'new.*usb|usb.*disconnect|USB Mass Storage|sd [a-z]: \[' \
    /var/log/syslog /var/log/messages /var/log/kern.log 2>/dev/null | \
    tail -30 | sed 's/^/       /'

echo -e "  $INFO Médias optiques détectés :"
dmesg 2>/dev/null | grep -iE 'cdrom|dvd|sr[0-9]' | sed 's/^/       /'

echo -e "  $INFO Interfaces réseau inhabituelles (adaptateurs USB réseau) :"
ip link show 2>/dev/null | grep -v 'lo:' | sed 's/^/       /'
for iface in $(ip link show 2>/dev/null | grep -oP '^\d+: \K[^:]+' | grep -v lo); do
    driver=$(ethtool -i "$iface" 2>/dev/null | grep driver | awk '{print $2}')
    bus=$(ethtool -i "$iface" 2>/dev/null | grep bus-info | awk '{print $2}')
    if echo "$bus" | grep -qi 'usb'; then
        echo -e "  $MED Interface réseau sur bus USB : $iface (driver: $driver, bus: $bus)"
    fi
done
echo ""

echo -e "$INFO 13. Capabilities inhabituelles sur les binaires..."
if command -v getcap >/dev/null 2>&1; then
    CAP_FILES=$(getcap -r / 2>/dev/null | grep -vE '^\s*$')
    if [ -n "$CAP_FILES" ]; then
        echo -e "  $INFO Binaires avec capabilities :"
        echo "$CAP_FILES" | while read -r line; do
            if echo "$line" | grep -qE 'cap_setuid|cap_sys_admin|cap_net_raw|cap_sys_ptrace|cap_dac_override|cap_net_admin'; then
                echo -e "  $HIGH Capability dangereuse : $line"
            else
                echo -e "  $MED $line"
            fi
        done
    else
        echo -e "  $LOW Aucune capability spéciale sur les binaires."
    fi
else
    echo -e "  $MED 'getcap' non disponible."
fi
echo ""

echo -e "$INFO 14. Namespaces et conteneurs cachés..."
echo -e "  $INFO Namespaces actifs par processus (PID non-standard) :"
lsns 2>/dev/null | grep -v '^\s*NS' | sed 's/^/       /'

echo -e "  $INFO Processus dans des namespaces réseau isolés :"
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    ns_net="/proc/$pid/ns/net"
    init_net="/proc/1/ns/net"
    if [ -L "$ns_net" ] && [ -L "$init_net" ]; then
        pid_ns=$(readlink "$ns_net" 2>/dev/null)
        init_ns=$(readlink "$init_net" 2>/dev/null)
        if [ "$pid_ns" != "$init_ns" ]; then
            cmdline=$(cat /proc/"$pid"/cmdline 2>/dev/null | tr '\0' ' ' | head -c 60)
            echo -e "  $MED PID $pid dans namespace réseau différent : $cmdline"
        fi
    fi
done | sort -u | head -20
echo ""

echo -e "$INFO 15. PAM — modules et configuration suspecte..."
echo -e "  $INFO Fichiers PAM modifiés récemment (<7j) :"
find /etc/pam.d /lib/security /usr/lib/security /lib/x86_64-linux-gnu/security \
    /usr/lib/x86_64-linux-gnu/security -type f -mtime -7 2>/dev/null | while read -r f; do
    echo -e "  $HIGH Fichier PAM modifié récemment : $f"
    ls -la "$f" 2>/dev/null | sed 's/^/       /'
done
echo -e "  $INFO Modules PAM inhabituels :"
grep -rh 'pam_' /etc/pam.d/ 2>/dev/null | grep -oE 'pam_[a-z0-9_]+\.so' | sort -u | \
    grep -vE 'pam_unix|pam_env|pam_limits|pam_nologin|pam_securetty|pam_cracklib|pam_pwquality|pam_deny|pam_permit|pam_motd|pam_lastlog|pam_mail|pam_selinux|pam_systemd|pam_keyinit|pam_loginuid|pam_namespace|pam_cap|pam_tally|pam_faillock|pam_access|pam_time|pam_group|pam_listfile|pam_umask' | \
    while read -r m; do
        echo -e "  $MED Module PAM inhabituel : $m"
done
echo ""

echo -e "$INFO 16. Fichiers /etc modifiés récemment (<24h)..."
find /etc -type f -mtime -1 2>/dev/null | while read -r f; do
    echo -e "  $MED Fichier /etc modifié <24h : $f ($(ls -la --time-style=long-iso "$f" 2>/dev/null | awk '{print $6,$7}'))"
done | head -40
echo ""

echo -e "$INFO 17. Historiques shell (présence, suppression, chiffrement)..."
for home_dir in $(awk -F: '($3 >= 1000 && $3 != 65534) || $3 == 0 {print $6}' /etc/passwd); do
    user=$(awk -F: -v h="$home_dir" '$6==h{print $1}' /etc/passwd | head -1)
    for hfile in .bash_history .zsh_history .sh_history .history; do
        fp="$home_dir/$hfile"
        if [ -f "$fp" ]; then
            size=$(stat -c%s "$fp" 2>/dev/null)
            if [ "$size" -eq 0 ] 2>/dev/null; then
                echo -e "  $HIGH Historique vidé (0 octet) : $fp ($user)"
            else
                echo -e "  $LOW Historique présent ($size octets) : $fp ($user)"
            fi
        fi
    done
    if [ -L "$home_dir/.bash_history" ]; then
        link_target=$(readlink "$home_dir/.bash_history" 2>/dev/null)
        echo -e "  $HIGH .bash_history est un lien symbolique vers : $link_target ($user)"
    fi
done
echo ""

echo -e "$INFO 18. Fichiers suspects (NOOWNER, world-writable, setuid dans /tmp)..."
echo -e "  $INFO Fichiers sans propriétaire (UID/GID inconnu) :"
find / -xdev \( $PRUNE \) -prune -o \( -nouser -o -nogroup \) -print 2>/dev/null | while read -r f; do
    echo -e "  $MED Fichier sans propriétaire valide : $f"
done | head -30

echo -e "  $INFO Fichiers world-writable dans des répertoires système :"
find /usr /bin /sbin /lib /lib64 /etc -xdev -perm -o+w -type f 2>/dev/null | while read -r f; do
    echo -e "  $HIGH Fichier système world-writable : $f"
done

echo -e "  $INFO Liens symboliques suspects (vers /dev/null ou fichiers supprimés) :"
find / -xdev \( $PRUNE \) -prune -o -type l -print 2>/dev/null | while read -r link; do
    target=$(readlink "$link" 2>/dev/null)
    if [ "$target" = "/dev/null" ]; then
        echo -e "  $MED Lien symbolique vers /dev/null : $link"
    elif [ -n "$target" ] && [ ! -e "$link" ]; then
        echo -e "  $MED Lien symbolique cassé : $link -> $target"
    fi
done | head -30
echo ""

echo -e "$INFO 19. Fichiers récents dans des emplacements sensibles (hors home, <24h)..."
for dir in /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin /usr/lib /lib; do
    find "$dir" -type f -mtime -1 2>/dev/null | while read -r f; do
        echo -e "  $HIGH Fichier récent dans $dir : $f ($(ls -la --time-style=long-iso "$f" | awk '{print $6,$7}'))"
    done
done
echo ""

echo -e "$INFO 20. Connexions et dernières authentifications..."
echo "---------------------------------------------------"
last -n 10 2>/dev/null
echo "---------------------------------------------------"
echo -e "$INFO Dernières tentatives d'authentification échouées :"
lastb -n 10 2>/dev/null || \
    grep -iE 'failed|invalid|authentication failure' /var/log/auth.log 2>/dev/null | tail -10 | sed 's/^/  /'

echo -e "$INFO Dernières utilisations de SUDO :"
if [ -f /var/log/auth.log ]; then
    grep 'COMMAND=' /var/log/auth.log 2>/dev/null | tail -10 | sed 's/^/  /'
elif [ -f /var/log/secure ]; then
    grep 'COMMAND=' /var/log/secure 2>/dev/null | tail -10 | sed 's/^/  /'
else
    journalctl _COMM=sudo -n 10 --no-pager 2>/dev/null | grep -i 'command=' | sed 's/^/  /'
fi

echo -e "$INFO Connexions SSH récentes (journal systemd) :"
journalctl _COMM=sshd -n 20 --no-pager 2>/dev/null | grep -iE 'Accepted|Failed|Invalid|disconnect' | sed 's/^/  /'
echo ""

echo -e "$INFO 21. Intégrité des paquets installés..."
case "$PKG_MGR" in
    dpkg)
        if command -v debsums >/dev/null 2>&1; then
            CHANGED=$(debsums -c 2>/dev/null)
            if [ -n "$CHANGED" ]; then
                echo -e "  $HIGH Fichiers de paquets modifiés (debsums) :"
                echo "$CHANGED" | sed 's/^/       -> /'
            else
                echo -e "  $LOW Aucune altération détectée par debsums."
            fi
        else
            echo -e "  $MED 'debsums' non installé — étape ignorée."
        fi
        ;;
    rpm)
        CHANGED=$(rpm -Va 2>/dev/null | grep -E '^..5|^missing' | head -n 30)
        if [ -n "$CHANGED" ]; then
            echo -e "  $HIGH Fichiers altérés / manquants (rpm -Va) :"
            echo "$CHANGED" | sed 's/^/       -> /'
        else
            echo -e "  $LOW Aucune altération détectée par rpm -Va."
        fi
        ;;
    *)
        echo -e "  $MED Gestionnaire de paquets non reconnu — étape ignorée."
        ;;
esac
echo ""

echo -e "$INFO 22. Analyse des scripts d'init et rc.local..."
for init_file in /etc/rc.local /etc/init.d/* /etc/rc*.d/*; do
    [ -f "$init_file" ] || continue
    hits=$(grep -siE 'wget|curl|nc |ncat|/dev/tcp|base64|python.*-c|bash -i|reverse' "$init_file" 2>/dev/null)
    if [ -n "$hits" ]; then
        echo -e "  $HIGH Commande suspecte dans $init_file :"
        echo "$hits" | sed 's/^/       /'
    fi
done
echo ""

echo -e "$INFO 23. Détection de sniffers / outils d'écoute réseau en cours..."
for tool in tcpdump wireshark tshark dumpcap ngrep dsniff ettercap bettercap; do
    pids=$(pgrep -x "$tool" 2>/dev/null)
    if [ -n "$pids" ]; then
        echo -e "  $HIGH Outil de capture réseau actif : $tool (PID $pids)"
    fi
done

echo -e "  $INFO Interfaces en mode promiscuous :"
ip link show 2>/dev/null | grep -i 'PROMISC' | sed 's/^/       /'
cat /proc/net/dev 2>/dev/null | while read -r iface rest; do
    iface=$(echo "$iface" | tr -d ':')
    flags=$(cat /proc/net/if_inet6 2>/dev/null | awk -v i="$iface" '$6==i{print $5}')
done
echo ""

echo -e "$INFO 24. Recherche de rootkits connus (signatures simples)..."
RKIT_HITS=0
for dir in /dev/MAKEDEV /dev/hd /usr/.bashrc /usr/.bash_history \
           /etc/.bashrc /etc/cron.d/.X /tmp/.X /tmp/.ICE \
           /lib/libproc.so /usr/lib/libproc.so; do
    if [ -e "$dir" ]; then
        echo -e "  $HIGH Artefact suspect (possible rootkit) : $dir"
        RKIT_HITS=$((RKIT_HITS+1))
    fi
done
for magic_name in ttyload ttymon mingetty agetty.real xsession; do
    found=$(find / -xdev \( $PRUNE \) -prune -o -name "$magic_name" -print 2>/dev/null)
    if [ -n "$found" ]; then
        echo -e "  $HIGH Fichier avec nom typique de rootkit : $found"
        RKIT_HITS=$((RKIT_HITS+1))
    fi
done
[ "$RKIT_HITS" -eq 0 ] && echo -e "  $LOW Aucun artefact rootkit connu trouvé (scan partiel)."

if command -v rkhunter >/dev/null 2>&1; then
    echo -e "  $INFO rkhunter disponible — lancement d'un scan rapide :"
    rkhunter --check --skip-keypress --quiet 2>/dev/null | grep -E 'Warning|Found' | sed 's/^/       /'
fi
if command -v chkrootkit >/dev/null 2>&1; then
    echo -e "  $INFO chkrootkit disponible — lancement :"
    chkrootkit 2>/dev/null | grep -iE 'infected|suspect|found' | sed 's/^/       /'
fi
echo ""

echo -e "$INFO 25. Variables d'environnement de processus sensibles..."
echo -e "  $INFO Recherche de secrets/tokens dans les envs de processus :"
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    env_file="/proc/$pid/environ"
    if [ -r "$env_file" ]; then
        env_content=$(tr '\0' '\n' < "$env_file" 2>/dev/null)
        secret_hits=$(echo "$env_content" | grep -iE '(password|passwd|secret|token|apikey|api_key|credential|private_key|aws_secret|db_pass)=' | grep -v '^PATH=')
        if [ -n "$secret_hits" ]; then
            cmdline=$(cat /proc/"$pid"/cmdline 2>/dev/null | tr '\0' ' ' | head -c 60)
            echo -e "  $MED PID $pid ($cmdline) contient des variables sensibles :"
            echo "$secret_hits" | sed 's/\(=\).*/\1[MASQUÉ]/' | sed 's/^/       /'
        fi
    fi
done | head -50
echo ""

echo -e "$INFO 26. Fichiers ACL étendues suspectes..."
if command -v getfacl >/dev/null 2>&1; then
    echo -e "  $INFO ACL étendues sur /etc, /usr/bin, /home :"
    for dir in /etc /usr/bin /home; do
        getfacl -R "$dir" 2>/dev/null | grep -E '^# file:|^user:|^group:' | \
        paste - - - 2>/dev/null | grep -v ':$' | while read -r file user group; do
            if echo "$user$group" | grep -qE 'user:.*:rw|group:.*:rw'; then
                echo -e "  $MED ACL non-standard sur : $file -> $user $group"
            fi
        done
    done
else
    echo -e "  $MED 'getfacl' non disponible."
fi
echo ""

echo -e "$INFO 27. Scan des fichiers de configuration sensibles accessibles en lecture..."
for f in /etc/shadow /etc/gshadow /etc/sudoers /root/.ssh/id_rsa \
         /root/.ssh/id_ed25519 /etc/ssl/private/; do
    if [ -e "$f" ]; then
        perms=$(stat -c '%a %U %G' "$f" 2>/dev/null)
        echo -e "  $INFO $f : permissions $perms"
        if stat -c '%a' "$f" 2>/dev/null | grep -qE '^[0-9](4|6|7)'; then
            echo -e "  $HIGH Fichier sensible lisible par groupe/autres : $f"
        fi
    fi
done
echo ""

echo "==============================================================="
echo "✅ Fin de l'audit IR-Hunter v4. Rapport : $OUTPUT_FILE"
echo "==============================================================="
}

case "$MODE" in
    baseline)
        do_baseline
        ;;
    check)
        if [ -e /dev/tty ] && [ -t 1 ]; then
            do_check 2>&1 | tee /dev/tty | sed 's/\x1b\[[0-9;]*m//g' > "$OUTPUT_FILE"
        else
            do_check 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tee "$OUTPUT_FILE"
        fi
        ;;
    audit|*)
        if [ -e /dev/tty ] && [ -t 1 ]; then
            run_audit 2>&1 | tee /dev/tty | sed 's/\x1b\[[0-9;]*m//g' > "$OUTPUT_FILE"
        else
            run_audit 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tee "$OUTPUT_FILE"
        fi
        ;;
esac
