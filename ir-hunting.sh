#!/bin/bash

set -o pipefail

# ----------------------------- Privilèges root -------------------------------
if [ "$EUID" -ne 0 ]; then
    echo -e "\e[31m[!] Ce script doit être lancé en tant que root (sudo).\e[0m"
    exit 1
fi

# ----------------------------- Couleurs / niveaux ----------------------------
RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; BLU='\033[0;34m'; NC='\033[0m'
HIGH="${RED}[🔴 HIGH]${NC}"
MED="${YEL}[🟡 MEDIUM]${NC}"
LOW="${GRN}[🟢 LOW]${NC}"
INFO="${BLU}[ℹ️ INFO]${NC}"

# ----------------------------- Variables globales ----------------------------
HOSTNAME=$(hostname)
DATE=$(date +%Y-%m-%d_%H-%M-%S)
OUTPUT_FILE="Audit_Global_${HOSTNAME}_${DATE}.txt"
BASELINE_DIR="/var/lib/ir-hunter/baseline"
MODE="${1:-audit}"

# Répertoires à exclure des recherches récursives (montages réseau, conteneurs…)
PRUNE='-path /proc -o -path /sys -o -path /run -o -path /snap -o -path /var/lib/docker'

# ----------------------------- Détection distro ------------------------------
PKG_MGR=""
DISTRO_ID=""
detect_distro() {
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
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

# =============================================================================
#  FONCTIONS DE COLLECTE (réutilisées par audit + baseline + check)
# =============================================================================

list_packages() {
    case "$PKG_MGR" in
        dpkg) dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null ;;
        rpm)  rpm -qa 2>/dev/null ;;
    esac
}

gather_cron() {
    # Crontabs système
    for f in /etc/crontab /etc/cron.d/*; do
        [ -f "$f" ] && grep -vE '^\s*(#|$)' "$f" 2>/dev/null | sed "s|^|$f: |"
    done
    # Répertoires périodiques
    for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        [ -d "$d" ] && find "$d" -maxdepth 1 -type f 2>/dev/null
    done
    # Crontabs utilisateurs
    for cdir in /var/spool/cron /var/spool/cron/crontabs; do
        if [ -d "$cdir" ]; then
            for uf in "$cdir"/*; do
                [ -f "$uf" ] && grep -vE '^\s*(#|$)' "$uf" 2>/dev/null | \
                    sed "s|^|crontab($(basename "$uf")): |"
            done
        fi
    done
}

# Génère un instantané complet dans le dossier passé en argument
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
    # Hash des binaires système (détecte un /bin/ls trojanisé)
    find /usr/bin /usr/sbin /bin /sbin -type f 2>/dev/null -exec sha256sum {} + 2>/dev/null \
        | sort -k2 > "$dir/bin_hashes.txt"
}

# =============================================================================
#  MODE BASELINE
# =============================================================================
do_baseline() {
    echo -e "$INFO Création de la baseline dans $BASELINE_DIR ..."
    echo -e "$INFO (à exécuter sur une machine que tu sais saine)"
    snapshot_to "$BASELINE_DIR"
    chmod -R 600 "$BASELINE_DIR" 2>/dev/null
    echo -e "  $LOW Baseline enregistrée :"
    ls -1 "$BASELINE_DIR" | sed 's/^/       -> /'
    echo -e "$INFO Conseil : copie ce dossier hors de la machine (clé USB / partage)"
    echo -e "       afin qu'un attaquant ne puisse pas le falsifier."
}

# =============================================================================
#  MODE CHECK (diff contre la baseline)
# =============================================================================
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
    echo "🔍 IR-Hunter v3 — MODE CHECK (diff baseline) sur $HOSTNAME"
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

    echo "==============================================================="
    echo "✅ Fin du check. Tout '+ AJOUTÉ' mérite une investigation."
    echo "==============================================================="
}

# =============================================================================
#  MODE AUDIT COMPLET
# =============================================================================
run_audit() {
echo "==============================================================="
echo "🔍 IR-Hunter v3 — audit approfondi sur $HOSTNAME ($DISTRO_ID / $PKG_MGR)"
echo "📅 Date : $(date)"
echo "📄 Rapport sauvegardé dans : $OUTPUT_FILE"
echo "==============================================================="
echo ""

# ---------------------------------------------------------
# 1. UTILISATEURS ET PRIVILÈGES
# ---------------------------------------------------------
echo -e "$INFO 1. Comptes UID 0, mots de passe vides, fichiers sensibles..."
for user in $(awk -F: '($3 == 0){print $1}' /etc/passwd); do
    if [ "$user" != "root" ]; then
        echo -e "  $HIGH Compte non-root avec UID 0 (privilèges max) : $user"
    else
        echo -e "  $LOW Compte root standard détecté."
    fi
done

# Mots de passe vides dans /etc/shadow
awk -F: '($2 == ""){print $1}' /etc/shadow 2>/dev/null | while read -r u; do
    [ -n "$u" ] && echo -e "  $HIGH Compte SANS mot de passe : $u"
done

# Date de dernière modification de passwd/shadow (un ajout récent = suspect)
echo -e "  $INFO Dernière modification des fichiers de comptes :"
ls -la --time-style=long-iso /etc/passwd /etc/shadow 2>/dev/null | \
    awk '{print "       -> "$6" "$7" "$8}'
echo ""

# ---------------------------------------------------------
# 2. CLÉS SSH (PERSISTANCE)
# ---------------------------------------------------------
echo -e "$INFO 2. Analyse des clés SSH (authorized_keys)..."
for home_dir in $(awk -F: '($3 >= 1000 && $3 != 65534) || $3 == 0 {print $6}' /etc/passwd); do
    if [ -f "$home_dir/.ssh/authorized_keys" ]; then
        echo -e "  $MED Fichier de clés trouvé : $home_dir/.ssh/authorized_keys"
        while read -r key; do
            [ -n "$key" ] && echo -e "       -> $key"
        done < "$home_dir/.ssh/authorized_keys"
    fi
done
echo ""

# ---------------------------------------------------------
# 3. TÂCHES PLANIFIÉES (CRON) — système + utilisateurs + périodiques
# ---------------------------------------------------------
echo -e "$INFO 3. Analyse des tâches Cron (toutes sources)..."
gather_cron | grep -E 'wget|curl|nc |ncat|/dev/tcp|bash -i|base64|python.*-c|sh ' | \
    while read -r line; do
        echo -e "  $HIGH Commande cron suspecte : $line"
    done
# Crontabs utilisateurs détaillées
for u in $(cut -d: -f1 /etc/passwd); do
    out=$(crontab -l -u "$u" 2>/dev/null | grep -vE '^\s*(#|$)')
    [ -n "$out" ] && echo -e "  $MED Crontab de '$u' :\n$(echo "$out" | sed 's/^/       /')"
done
echo ""

# ---------------------------------------------------------
# 4. SERVICES & TIMERS SYSTEMD
# ---------------------------------------------------------
echo -e "$INFO 4. Services systemd récents et timers..."
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
# Services utilisateurs (souvent oubliés)
find /home/*/.config/systemd/user /root/.config/systemd/user -type f -name "*.service" \
    -mtime -2 2>/dev/null | while read -r s; do
        echo -e "  $HIGH Service utilisateur récent : $s"
done
# Timers (équivalent moderne de cron)
echo -e "  $INFO Timers systemd actifs :"
systemctl list-timers --all --no-pager 2>/dev/null | sed 's/^/       /'
echo ""

# ---------------------------------------------------------
# 5. ZONES TEMPORAIRES INSCRIPTIBLES (exécutables ELF récents)
# ---------------------------------------------------------
echo -e "$INFO 5. Exécutables ELF récents dans /tmp, /var/tmp, /dev/shm..."
FOUND=0
for f in $(find /tmp /var/tmp /dev/shm -type f -mtime -7 2>/dev/null); do
    if file "$f" 2>/dev/null | grep -q 'ELF'; then
        echo -e "  $HIGH Binaire ELF en zone temporaire : $f"
        echo -e "       $(file "$f" | cut -d: -f2-)"
        FOUND=1
    fi
done
[ "$FOUND" -eq 0 ] && echo -e "  $LOW Aucun binaire ELF récent suspect dans les zones temporaires."
echo ""

# ---------------------------------------------------------
# 6. BINAIRES SUID / SGID RÉCENTS (ÉLÉVATION)
# ---------------------------------------------------------
echo -e "$INFO 6. Backdoors SUID/SGID créés récemment..."
SUID_FILES=$(find / -xdev \( $PRUNE \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -mtime -2 -print 2>/dev/null)
if [ -n "$SUID_FILES" ]; then
    echo -e "  $HIGH Binaires SUID/SGID modifiés/créés <48h :"
    echo "$SUID_FILES" | sed 's/^/       -> /'
else
    echo -e "  $LOW Pas de binaire SUID/SGID récent suspect."
fi
echo ""

# ---------------------------------------------------------
# 7. PERSISTANCE : ld.so.preload + fichiers RC des shells
# ---------------------------------------------------------
echo -e "$INFO 7. Détournement de bibliothèques et persistance via shells..."
if [ -s /etc/ld.so.preload ]; then
    echo -e "  $HIGH /etc/ld.so.preload présent (technique de rootkit) :"
    sed 's/^/       -> /' /etc/ld.so.preload
else
    echo -e "  $LOW /etc/ld.so.preload absent ou vide."
fi
RC_HITS=$(grep -RsiE 'curl|wget|/dev/tcp|nc |ncat|base64 -d|eval ' \
    /etc/profile /etc/profile.d/ /etc/bash.bashrc \
    /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile 2>/dev/null)
if [ -n "$RC_HITS" ]; then
    echo -e "  $HIGH Commandes suspectes dans des fichiers de démarrage de shell :"
    echo "$RC_HITS" | sed 's/^/       -> /'
else
    echo -e "  $LOW Aucun motif suspect dans les fichiers RC."
fi
echo ""

# ---------------------------------------------------------
# 8. FICHIERS IMMUABLES (chattr +i — anti-suppression)
# ---------------------------------------------------------
echo -e "$INFO 8. Recherche de fichiers rendus immuables (chattr +i)..."
IMMUT=$(lsattr -R /etc /usr/bin /usr/sbin /tmp /var/tmp 2>/dev/null | grep -- '----i' )
if [ -n "$IMMUT" ]; then
    echo -e "  $HIGH Fichiers immuables détectés (attention si non légitimes) :"
    echo "$IMMUT" | sed 's/^/       -> /'
else
    echo -e "  $LOW Aucun fichier immuable inhabituel détecté."
fi
echo ""

# ---------------------------------------------------------
# 9. RÉSEAU : PORTS EN ÉCOUTE + CONNEXIONS SORTANTES
# ---------------------------------------------------------
echo -e "$INFO 9. Analyse réseau (écoute + connexions établies)..."
echo -e "  $INFO Ports en écoute :"
ss -tulpn 2>/dev/null | sed 's/^/       /'
echo -e "  $INFO Connexions sortantes établies (reverse shells potentielles) :"
ss -tnp state established 2>/dev/null | sed 's/^/       /'

# Processus à l'écoute dont le binaire est suspect ou supprimé
for pid in $(ss -tulpnH 2>/dev/null | grep -oP 'pid=\K[0-9]+' | sort -u); do
    exe=$(ls -l /proc/"$pid"/exe 2>/dev/null | awk -F'-> ' '{print $2}')
    case "$exe" in
        *deleted*|/tmp/*|/var/tmp/*|/dev/shm/*)
            echo -e "  $HIGH Processus en écoute suspect : PID $pid -> $exe" ;;
    esac
done
echo ""

# ---------------------------------------------------------
# 10. PROCESSUS FANTÔMES (binaire supprimé du disque)
# ---------------------------------------------------------
echo -e "$INFO 10. Processus actifs dont le binaire a été supprimé..."
DELETED_PROCS=$(ls -al /proc/*/exe 2>/dev/null | grep 'deleted')
if [ -n "$DELETED_PROCS" ]; then
    echo -e "  $HIGH Processus dont le binaire source a été supprimé :"
    echo "$DELETED_PROCS" | awk '{print "       -> "$9" "$10" "$11}'
else
    echo -e "  $LOW Aucun processus fantôme détecté."
fi
echo ""

# ---------------------------------------------------------
# 11. LOGS : DERNIÈRES CONNEXIONS ET SUDO
# ---------------------------------------------------------
echo -e "$INFO 11. Dernières connexions réussies :"
echo "---------------------------------------------------"
last -n 5 2>/dev/null
echo "---------------------------------------------------"

echo -e "$INFO     Dernières utilisations de SUDO :"
if [ -f /var/log/auth.log ]; then            # Debian / Ubuntu
    grep 'COMMAND=' /var/log/auth.log 2>/dev/null | tail -n 5 | sed 's/^/  /'
elif [ -f /var/log/secure ]; then            # RHEL / Fedora (fichier)
    grep 'COMMAND=' /var/log/secure 2>/dev/null | tail -n 5 | sed 's/^/  /'
else                                          # Systemd pur (journald)
    journalctl _COMM=sudo -n 5 --no-pager 2>/dev/null | grep -i 'command=' | sed 's/^/  /'
fi
echo ""

# ---------------------------------------------------------
# 12. INTÉGRITÉ DES PAQUETS INSTALLÉS
# ---------------------------------------------------------
echo -e "$INFO 12. Vérification d'intégrité des binaires fournis par les paquets..."
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
            echo -e "  $MED 'debsums' non installé (apt install debsums) — étape ignorée."
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

echo "==============================================================="
echo "✅ Fin de l'audit. Rapport complet : $OUTPUT_FILE"
echo "==============================================================="
}

# =============================================================================
#  AIGUILLAGE DES MODES + écriture du rapport (pipeline sans race condition)
# =============================================================================
case "$MODE" in
    baseline)
        do_baseline
        ;;
    check)
        # Pipeline réel à 3 étages : bash attend toute la chaîne -> pas de troncature
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
