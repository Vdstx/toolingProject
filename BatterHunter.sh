#!/usr/bin/env bash
#
# hunter.sh - Détection de backdoors / persistance sur machine Linux
# Compatible Debian et Fedora (n'utilise que des outils standards des deux familles)
#
# Usage:
#   sudo ./hunter.sh                 # affiche le rapport dans le terminal + fichier log
#   sudo ./hunter.sh -o rapport.txt  # choisir le fichier de sortie
#   sudo ./hunter.sh -q              # mode rapide (skip les find longs sur /)
#
# Le script ne MODIFIE rien sur le système. Il ne fait que lire et lister.
# Plus on est root, plus la couverture est bonne (shadow, crontabs des autres
# utilisateurs, /proc/*/environ, ld.so.preload, etc.)

set -uo pipefail

# ---------------------------------------------------------------------------
# Setup / options
# ---------------------------------------------------------------------------

QUICK=0
OUTFILE="hunter_report_$(date +%Y%m%d_%H%M%S).txt"

while getopts "qo:h" opt; do
    case "$opt" in
        q) QUICK=1 ;;
        o) OUTFILE="$OPTARG" ;;
        h)
            echo "Usage: $0 [-q] [-o fichier_sortie.txt]"
            echo "  -q  mode rapide (évite les recherches longues type find / entier)"
            echo "  -o  fichier de sortie du rapport (par défaut hunter_report_<date>.txt)"
            exit 0
            ;;
        *) ;;
    esac
done

# Couleurs (désactivées si pas de terminal)
if [ -t 1 ]; then
    C_RED='\033[1;31m'; C_YEL='\033[1;33m'; C_GRN='\033[1;32m'; C_BLU='\033[1;34m'; C_CYA='\033[1;36m'; C_RST='\033[0m'
else
    C_RED=''; C_YEL=''; C_GRN=''; C_BLU=''; C_CYA=''; C_RST=''
fi

CRIT_COUNT=0
WARN_COUNT=0
INFO_COUNT=0

# Tout ce qui est affiché passe aussi dans le fichier de rapport (sans couleurs)
exec > >(tee >(sed -E 's/\x1B\[[0-9;]*[a-zA-Z]//g' >> "$OUTFILE")) 2>&1

section() {
    echo ""
    echo -e "${C_BLU}========================================================================${C_RST}"
    echo -e "${C_BLU} $1${C_RST}"
    echo -e "${C_BLU}========================================================================${C_RST}"
}

crit() { echo -e "${C_RED}[CRITIQUE]${C_RST} $*"; CRIT_COUNT=$((CRIT_COUNT+1)); }
warn() { echo -e "${C_YEL}[ATTENTION]${C_RST} $*"; WARN_COUNT=$((WARN_COUNT+1)); }
info() { echo -e "${C_CYA}[INFO]${C_RST} $*"; INFO_COUNT=$((INFO_COUNT+1)); }
ok()   { echo -e "${C_GRN}[OK]${C_RST} $*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# Bannière
# ---------------------------------------------------------------------------

echo -e "${C_BLU}"
echo "  _   _             _            "
echo " | | | |_   _ _ __ | |_ ___ _ __ "
echo " | |_| | | | | '_ \\| __/ _ \\ '__|"
echo " |  _  | |_| | | | | ||  __/ |   "
echo " |_| |_|\\__,_|_| |_|\\__\\___|_|   "
echo -e "${C_RST}"
echo "Détection de backdoors et persistance - Debian/Fedora"
echo "Date          : $(date)"
echo "Hostname      : $(hostname 2>/dev/null)"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "Distribution  : ${PRETTY_NAME:-inconnue}"
fi
echo "Lancé en tant que : $(id -un) (UID $(id -u))"
echo "Rapport écrit dans : $OUTFILE"

if [ "$(id -u)" -ne 0 ]; then
    warn "Script lancé SANS les droits root : certaines vérifications (shadow, crontabs des autres users, /proc/*/environ, modules cachés) seront incomplètes. Relance avec sudo pour un audit complet."
fi

# ===========================================================================
# 1. CRON (système + utilisateurs)
# ===========================================================================
section "1. Tâches planifiées (cron / anacron)"

SUSPICIOUS_PATTERN='curl |wget |nc -e|ncat |/dev/tcp/|base64 -d|base64 --decode|bash -i|python.*socket|perl -e|mkfifo|chmod \+s|setuid|0\.0\.0\.0/[0-9]'

for f in /etc/crontab /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.weekly/* /etc/cron.monthly/* /etc/anacrontab; do
    [ -f "$f" ] || continue
    if grep -qE "$SUSPICIOUS_PATTERN" "$f" 2>/dev/null; then
        crit "Contenu suspect dans $f :"
        grep -nE "$SUSPICIOUS_PATTERN" "$f" 2>/dev/null | sed 's/^/      /'
    fi
    # mtime récent (< 7 jours) sur un fichier cron système = suspect
    if [ -n "$(find "$f" -mtime -7 2>/dev/null)" ]; then
        warn "Fichier cron modifié il y a moins de 7 jours : $f ($(stat -c '%y' "$f" 2>/dev/null))"
    fi
done

# Crontabs utilisateurs (chemin diffère selon distro)
CRONTAB_DIRS="/var/spool/cron/crontabs /var/spool/cron"
for d in $CRONTAB_DIRS; do
    [ -d "$d" ] || continue
    for cf in "$d"/*; do
        [ -f "$cf" ] || continue
        user=$(basename "$cf")
        if grep -qE "$SUSPICIOUS_PATTERN" "$cf" 2>/dev/null; then
            crit "Crontab de l'utilisateur '$user' contient une commande suspecte ($cf) :"
            grep -nE "$SUSPICIOUS_PATTERN" "$cf" 2>/dev/null | sed 's/^/      /'
        fi
        info "Crontab présente pour l'utilisateur '$user' -> à relire manuellement : $cf"
    done
done

# Tentative via la commande crontab pour chaque utilisateur (si root)
if [ "$(id -u)" -eq 0 ] && have crontab; then
    for u in $(cut -d: -f1 /etc/passwd); do
        c=$(crontab -l -u "$u" 2>/dev/null)
        if [ -n "$c" ]; then
            echo "$c" | grep -qE "$SUSPICIOUS_PATTERN" && crit "crontab -l de '$u' contient un motif suspect"
        fi
    done
fi

# ===========================================================================
# 2. SERVICES SYSTEMD / TIMERS
# ===========================================================================
section "2. Services et timers systemd"

if have systemctl; then
    systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}' | while read -r svc; do
        unitfile=$(systemctl show -p FragmentPath --value "$svc" 2>/dev/null)
        [ -z "$unitfile" ] && continue
        execstart=$(systemctl show -p ExecStart --value "$svc" 2>/dev/null)

        case "$execstart" in
            *"/tmp/"*|*"/dev/shm/"*|*"/var/tmp/"*|*"/home/"*) 
                crit "Service '$svc' lance un binaire depuis un emplacement non-standard : $execstart (unit: $unitfile)" ;;
        esac

        if [ -n "$(find "$unitfile" -mtime -7 2>/dev/null)" ]; then
            warn "Unit systemd modifiée récemment (<7j) : $unitfile (service: $svc)"
        fi
    done

    echo ""
    info "Timers actifs (à vérifier manuellement, technique de persistance classique) :"
    systemctl list-timers --all --no-legend 2>/dev/null | sed 's/^/      /'
else
    info "systemctl non trouvé, étape ignorée."
fi

# ===========================================================================
# 3. CLES SSH AUTORISEES
# ===========================================================================
section "3. Clés SSH autorisées (~/.ssh/authorized_keys)"

while IFS=: read -r user _ uid _ _ home shell; do
    ak="$home/.ssh/authorized_keys"
    [ -f "$ak" ] || continue
    nkeys=$(grep -cE '^(ssh-|ecdsa-|sk-)' "$ak" 2>/dev/null)
    mtime=$(stat -c '%y' "$ak" 2>/dev/null)
    warn "authorized_keys présent pour '$user' (UID $uid) : $nkeys clé(s), modifié le $mtime -> $ak"
    if [ "$user" = "root" ] || [ "$uid" -eq 0 ]; then
        crit "Le compte root (ou UID 0 '$user') possède un authorized_keys : $ak (à valider absolument)"
    fi
    if [ -n "$(find "$ak" -mtime -7 2>/dev/null)" ]; then
        crit "authorized_keys de '$user' modifié il y a moins de 7 jours -> clé potentiellement ajoutée par un attaquant"
    fi
done < /etc/passwd

# Détection de clés identiques sur plusieurs comptes (déploiement de masse = backdoor)
if have md5sum; then
    find / -path /proc -prune -o -name authorized_keys -print 2>/dev/null | while read -r f; do
        md5sum "$f" 2>/dev/null
    done | sort | uniq -c -w32 | awk '$1>1{print}' | while read -r line; do
        warn "Plusieurs authorized_keys identiques détectés (même clé déployée sur plusieurs comptes) : $line"
    done
fi

# ===========================================================================
# 4. CONFIGURATION SSHD
# ===========================================================================
section "4. Configuration du serveur SSH (/etc/ssh/sshd_config)"

SSHD_CONF="/etc/ssh/sshd_config"
if [ -f "$SSHD_CONF" ]; then
    val_root=$(grep -iE '^\s*PermitRootLogin' "$SSHD_CONF" /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tail -1)
    val_pass=$(grep -iE '^\s*PasswordAuthentication' "$SSHD_CONF" /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tail -1)
    val_akc=$(grep -iE '^\s*AuthorizedKeysCommand' "$SSHD_CONF" /etc/ssh/sshd_config.d/*.conf 2>/dev/null)
    val_akf=$(grep -iE '^\s*AuthorizedKeysFile' "$SSHD_CONF" /etc/ssh/sshd_config.d/*.conf 2>/dev/null)
    val_port=$(grep -iE '^\s*Port' "$SSHD_CONF" /etc/ssh/sshd_config.d/*.conf 2>/dev/null)

    echo "$val_root" | grep -qi 'yes' && warn "PermitRootLogin yes activé dans sshd_config"
    echo "$val_pass" | grep -qi 'yes' && warn "PasswordAuthentication yes activé (le brute-force/mot de passe faible devient possible)"
    [ -n "$val_akc" ] && crit "AuthorizedKeysCommand personnalisé détecté (mécanisme d'auth alternatif, vérifier le binaire visé) : $val_akc"
    [ -n "$val_akf" ] && warn "AuthorizedKeysFile non standard configuré : $val_akf"
    [ -n "$val_port" ] && info "Port(s) SSH configuré(s) : $val_port"

    if [ -n "$(find "$SSHD_CONF" -mtime -7 2>/dev/null)" ]; then
        warn "sshd_config modifié il y a moins de 7 jours"
    fi

    if grep -qiE '^\s*Match' "$SSHD_CONF" 2>/dev/null; then
        info "Bloc(s) 'Match' présent(s) dans sshd_config (règles conditionnelles), à relire :"
        grep -niE '^\s*Match' "$SSHD_CONF" | sed 's/^/      /'
    fi
else
    info "sshd_config non trouvé."
fi

# ===========================================================================
# 5. COMPTES UTILISATEURS / SHADOW
# ===========================================================================
section "5. Comptes utilisateurs suspects"

awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | while read -r u; do
    crit "Compte avec UID 0 (root) autre que 'root' détecté : $u  <-- backdoor classique"
done

# comptes avec shell interactif mais home/usage inhabituel
awk -F: '($7=="/bin/bash" || $7=="/bin/sh" || $7=="/bin/zsh") {print $1":"$3":"$6":"$7}' /etc/passwd | while IFS=: read -r u uid home shell; do
    if [ "$uid" -lt 1000 ] && [ "$u" != "root" ]; then
        warn "Compte système (UID $uid) avec un shell interactif ($shell) : $u -> potentiellement un compte de service transformé en backdoor"
    fi
done

# mtime de /etc/passwd et /etc/shadow
for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do
    [ -f "$f" ] || continue
    if [ -n "$(find "$f" -mtime -3 2>/dev/null)" ]; then
        warn "$f modifié il y a moins de 3 jours -> vérifier les comptes ajoutés/modifiés"
    fi
done

# comptes sans mot de passe (nécessite root pour lire /etc/shadow)
if [ -r /etc/shadow ]; then
    awk -F: '($2=="" || $2=="!" && $1!~"^(nobody|sync)$"){print $1":"$2}' /etc/shadow | while IFS=: read -r u pw; do
        if [ "$pw" = "" ]; then
            crit "Compte '$u' SANS mot de passe (champ vide dans /etc/shadow) -> connexion sans authentification possible"
        fi
    done
else
    info "/etc/shadow illisible (lancer en root pour vérifier les mots de passe vides)."
fi

# ===========================================================================
# 6. BINAIRES SUID / SGID
# ===========================================================================
section "6. Binaires SUID / SGID inhabituels"

# Liste blanche de binaires SUID/SGID courants sur Debian/Fedora
WHITELIST_SUID="/usr/bin/passwd /usr/bin/sudo /usr/bin/su /usr/bin/mount /usr/bin/umount \
/usr/bin/ping /usr/bin/ping6 /usr/bin/pkexec /usr/bin/gpasswd /usr/bin/chsh /usr/bin/chfn \
/usr/bin/newgrp /usr/bin/fusermount /usr/bin/fusermount3 /usr/bin/chage /usr/bin/expiry \
/usr/bin/crontab /usr/sbin/unix_chkpwd /usr/sbin/pam_extrausers_chkpwd /usr/lib/polkit-1/polkit-agent-helper-1 \
/usr/bin/mount.nfs /usr/bin/Xorg /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/bin/at \
/usr/bin/wall /usr/bin/write /usr/bin/su.shadow /usr/bin/umount.udisks2 /usr/bin/staprun"

if [ "$QUICK" -eq 1 ]; then
    SEARCH_PATHS="/usr /bin /sbin /opt /home /tmp /var/tmp /dev/shm"
else
    SEARCH_PATHS="/"
fi

find $SEARCH_PATHS -xdev -path /proc -prune -o \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null | sort -u | while read -r bin; do
    case " $WHITELIST_SUID " in
        *" $bin "*) continue ;;
    esac
    case "$bin" in
        /tmp/*|/var/tmp/*|/dev/shm/*|/home/*)
            crit "Binaire SUID/SGID dans un répertoire non-système (très suspect) : $bin ($(stat -c '%A %U %G' "$bin" 2>/dev/null))" ;;
        *)
            warn "Binaire SUID/SGID hors liste blanche : $bin ($(stat -c '%A %U %G' "$bin" 2>/dev/null))" ;;
    esac
done

# ===========================================================================
# 7. LD_PRELOAD / library hijacking
# ===========================================================================
section "7. LD_PRELOAD et hijacking de librairies"

if [ -f /etc/ld.so.preload ] && [ -s /etc/ld.so.preload ]; then
    crit "/etc/ld.so.preload existe et N'EST PAS VIDE -> technique de backdoor classique (injection de .so dans tous les processus) :"
    cat /etc/ld.so.preload | sed 's/^/      /'
elif [ -f /etc/ld.so.preload ]; then
    info "/etc/ld.so.preload existe mais est vide (normal sur la plupart des systèmes)."
fi

env | grep -q '^LD_PRELOAD=' && crit "Variable d'environnement LD_PRELOAD active dans le shell courant : $LD_PRELOAD"

if [ "$(id -u)" -eq 0 ]; then
    for envf in /proc/[0-9]*/environ; do
        [ -r "$envf" ] || continue
        if tr '\0' '\n' < "$envf" 2>/dev/null | grep -q '^LD_PRELOAD='; then
            pid=$(echo "$envf" | grep -oE '[0-9]+')
            crit "Processus PID $pid lancé avec LD_PRELOAD défini -> $(tr '\0' '\n' < "$envf" 2>/dev/null | grep '^LD_PRELOAD=')"
        fi
    done
fi

# ===========================================================================
# 8. FICHIERS DE DEMARRAGE SHELL / PATH
# ===========================================================================
section "8. Fichiers de démarrage shell (.bashrc, profile...) et PATH"

RC_PATTERN='LD_PRELOAD=|curl .*\|.*sh|wget .*\|.*sh|base64 -d|base64 --decode|nc -e|/dev/tcp/|unset HISTFILE|HISTSIZE=0|history -c|export PATH=.*\.|alias (ls|cat|ps|netstat|ss|find)='

for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/profile.d/*.sh; do
    [ -f "$f" ] || continue
    if grep -qE "$RC_PATTERN" "$f" 2>/dev/null; then
        crit "Motif suspect dans $f :"
        grep -nE "$RC_PATTERN" "$f" | sed 's/^/      /'
    fi
done

while IFS=: read -r user _ uid _ _ home shell; do
    for rc in "$home/.bashrc" "$home/.bash_profile" "$home/.profile" "$home/.zshrc" "$home/.bash_login"; do
        [ -f "$rc" ] || continue
        if grep -qE "$RC_PATTERN" "$rc" 2>/dev/null; then
            crit "Motif suspect dans $rc (utilisateur $user) :"
            grep -nE "$RC_PATTERN" "$rc" | sed 's/^/      /'
        fi
    done
done < /etc/passwd

# PATH actuel contenant '.' ou un répertoire world-writable en tête
case ":$PATH:" in
    *":.:"*|"::"*|*":.:"|.:* ) crit "Le répertoire courant '.' est présent dans le PATH -> exécution de binaire piégé possible" ;;
esac
echo "$PATH" | tr ':' '\n' | while read -r p; do
    [ -d "$p" ] || continue
    if [ -w "$p" ] && [ "$(stat -c '%U' "$p" 2>/dev/null)" != "$(id -un)" ]; then
        perm=$(stat -c '%A' "$p" 2>/dev/null)
        case "$perm" in
            *w*) [ "${perm: -1}" = "w" ] && warn "Répertoire du PATH world-writable : $p ($perm) -> hijacking de binaire possible" ;;
        esac
    fi
done

# ===========================================================================
# 9. PROCESSUS AVEC BINAIRE SUPPRIME DU DISQUE
# ===========================================================================
section "9. Processus exécutant un binaire supprimé du disque"

for p in /proc/[0-9]*; do
    pid=$(basename "$p")
    [ -L "$p/exe" ] || continue
    target=$(readlink "$p/exe" 2>/dev/null) || continue
    case "$target" in
        *"(deleted)"*)
            cmdline=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
            crit "PID $pid exécute un binaire SUPPRIMÉ du disque : $target -- cmdline: $cmdline"
            ;;
    esac
done

# ===========================================================================
# 10. PORTS EN ECOUTE / RESEAU
# ===========================================================================
section "10. Ports en écoute et connexions réseau"

if have ss; then
    echo "Sockets en écoute (TCP/UDP) :"
    ss -tulpn 2>/dev/null | sed 's/^/      /'
    ss -tulpn 2>/dev/null | tail -n +2 | while read -r line; do
        proc=$(echo "$line" | grep -oE 'users:\(\("[^"]+"' | sed 's/users:((//;s/"//g')
        case "$line" in
            *"/tmp/"*|*"/dev/shm/"*|*"/var/tmp/"*) crit "Process réseau lancé depuis un emplacement non-standard : $line" ;;
        esac
        if [ -z "$proc" ] && [ "$(id -u)" -eq 0 ]; then
            warn "Socket en écoute sans nom de process résolu (process caché possible) : $line"
        fi
    done
elif have netstat; then
    netstat -tulpn 2>/dev/null | sed 's/^/      /'
else
    info "Ni ss ni netstat trouvés, étape ignorée."
fi

echo ""
echo "Connexions établies sortantes (ESTABLISHED) :"
if have ss; then
    ss -tnp state established 2>/dev/null | sed 's/^/      /'
fi

# ===========================================================================
# 11. FICHIERS CACHES / EXECUTABLES DANS TMP
# ===========================================================================
section "11. Fichiers cachés ou exécutables dans /tmp, /var/tmp, /dev/shm"

for d in /tmp /var/tmp /dev/shm; do
    [ -d "$d" ] || continue
    find "$d" -maxdepth 3 -name ".*" -type f 2>/dev/null | while read -r f; do
        warn "Fichier caché dans $d : $f ($(stat -c '%A %U %y' "$f" 2>/dev/null))"
    done
    find "$d" -maxdepth 3 -type f -perm -111 2>/dev/null | while read -r f; do
        crit "Fichier EXECUTABLE dans $d (rare en usage normal) : $f ($(stat -c '%A %U %y' "$f" 2>/dev/null))"
    done
done

# ===========================================================================
# 12. FICHIERS SYSTEME MODIFIES RECEMMENT
# ===========================================================================
section "12. Fichiers système modifiés récemment (<48h)"

if [ "$QUICK" -eq 0 ]; then
    info "Recherche en cours (peut prendre du temps, utiliser -q pour passer cette étape)..."
    find /etc /usr/bin /usr/sbin /bin /sbin /usr/lib/systemd -type f -mtime -2 2>/dev/null | while read -r f; do
        warn "Fichier système modifié il y a moins de 48h : $f ($(stat -c '%y' "$f" 2>/dev/null))"
    done
    echo ""
    info "Note: une mise à jour système (apt/dnf upgrade) légitime peut aussi générer ces résultats. Vérifier le contexte."
else
    info "Mode rapide (-q) : étape ignorée."
fi

# ===========================================================================
# 13. RC.LOCAL / INIT.D / GENERATEURS SYSTEMD
# ===========================================================================
section "13. rc.local, init.d, générateurs systemd"

if [ -f /etc/rc.local ]; then
    if [ -x /etc/rc.local ]; then
        warn "/etc/rc.local existe et est exécutable -> contenu à vérifier :"
        cat /etc/rc.local | sed 's/^/      /'
    fi
fi

if [ -d /etc/init.d ]; then
    find /etc/init.d -maxdepth 1 -type f -mtime -7 2>/dev/null | while read -r f; do
        warn "Script init.d modifié récemment : $f"
    done
fi

for gd in /etc/systemd/system-generators /usr/local/lib/systemd/system-generators; do
    [ -d "$gd" ] || continue
    find "$gd" -type f 2>/dev/null | while read -r f; do
        warn "Générateur systemd personnalisé présent (exécuté à chaque boot) : $f"
    done
done

# ===========================================================================
# 14. MODULES NOYAU SUSPECTS
# ===========================================================================
section "14. Modules noyau (rootkits LKM)"

if have lsmod; then
    lsmod | tail -n +2 | awk '{print $1}' | while read -r mod; do
        info_mod=$(modinfo "$mod" 2>/dev/null)
        if [ -z "$info_mod" ]; then
            crit "Module noyau '$mod' chargé SANS information modinfo disponible -> possible module caché/non présent sur disque (technique de rootkit LKM)"
            continue
        fi
        fname=$(echo "$info_mod" | awk -F': *' '/^filename:/{print $2}')
        if [ -n "$fname" ] && [ ! -f "$fname" ]; then
            crit "Module noyau '$mod' référence un fichier introuvable sur disque : $fname"
        fi
    done
else
    info "lsmod non trouvé, étape ignorée."
fi

# ===========================================================================
# 15. SUDOERS / NOPASSWD
# ===========================================================================
section "15. Configuration sudoers"

for f in /etc/sudoers /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    if grep -qE 'NOPASSWD' "$f" 2>/dev/null; then
        warn "Règle NOPASSWD trouvée dans $f :"
        grep -nE 'NOPASSWD' "$f" 2>/dev/null | sed 's/^/      /'
    fi
    if [ -n "$(find "$f" -mtime -7 2>/dev/null)" ]; then
        warn "Fichier sudoers modifié il y a moins de 7 jours : $f"
    fi
    if grep -qE '^\s*ALL\s+ALL=\(ALL.*ALL\)\s+ALL\s*$' "$f" 2>/dev/null; then
        crit "Règle sudo 'ALL ALL=(ALL) ALL' (tout utilisateur peut sudo sans restriction) trouvée dans $f"
    fi
done

# ===========================================================================
# 16. CAPABILITIES LINUX
# ===========================================================================
section "16. Capabilities Linux anormales (getcap)"

if have getcap; then
    if [ "$QUICK" -eq 1 ]; then
        CAP_PATHS="/usr /bin /sbin /opt /home /tmp /var/tmp /dev/shm"
    else
        CAP_PATHS="/"
    fi
    getcap -r $CAP_PATHS 2>/dev/null | while read -r line; do
        case "$line" in
            *cap_setuid*|*cap_setgid*|*cap_sys_admin*|*cap_sys_ptrace*|*cap_dac_override*|*cap_net_raw+ep*)
                crit "Capability puissante détectée : $line" ;;
            *)
                info "Capability présente (à vérifier) : $line" ;;
        esac
    done
else
    info "getcap non trouvé, étape ignorée."
fi

# ===========================================================================
# 17. PAM
# ===========================================================================
section "17. Modules PAM"

if [ -d /etc/pam.d ]; then
    find /etc/pam.d -type f -mtime -7 2>/dev/null | while read -r f; do
        warn "Fichier PAM modifié récemment : $f"
    done
    # pam_exec.so peut exécuter n'importe quelle commande à l'authentification -> critique
    grep -lE 'pam_exec\.so' /etc/pam.d/* 2>/dev/null | while read -r f; do
        crit "Module pam_exec.so référencé dans $f (peut exécuter une commande arbitraire à l'auth/login) :"
        grep -nE 'pam_exec\.so' "$f" | sed 's/^/      /'
    done
    # pam_succeed_if.so peut servir à contourner une condition d'auth -> attention
    grep -lE 'pam_succeed_if\.so' /etc/pam.d/* 2>/dev/null | while read -r f; do
        warn "Module pam_succeed_if.so référencé dans $f (vérifier la condition, peut servir à bypasser l'auth pour un user/groupe précis) :"
        grep -nE 'pam_succeed_if\.so' "$f" | sed 's/^/      /'
    done
    # pam_permit.so isolé dans common-* est normal sous Debian (squelette pam-auth-update).
    # On ne le signale que s'il apparaît dans des fichiers sensibles hors common-* (sshd, su, sudo, login)
    grep -lE 'pam_permit\.so' /etc/pam.d/sshd /etc/pam.d/su /etc/pam.d/sudo /etc/pam.d/login /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null | while read -r f; do
        crit "pam_permit.so référencé directement dans $f (autorise sans condition) -> très suspect sur ce fichier précis :"
        grep -nE 'pam_permit\.so' "$f" | sed 's/^/      /'
    done
fi

for libdir in /lib/security /usr/lib/security /usr/lib64/security /lib64/security; do
    [ -d "$libdir" ] || continue
    find "$libdir" -name '*.so' -mtime -30 2>/dev/null | while read -r so; do
        warn "Librairie PAM (.so) modifiée récemment : $so"
    done
done

# ===========================================================================
# 18. PROCESSUS AVEC PATTERNS DE REVERSE SHELL
# ===========================================================================
section "18. Processus en cours avec patterns suspects (reverse shell, etc.)"

PROC_PATTERN='nc .*-e|ncat .*-e|/dev/tcp/|/dev/udp/|socat .*exec|bash -i|sh -i|python.*socket\.|perl.*socket|mkfifo .*nc|0\.0\.0\.0/0'

ps -eo pid,user,cmd 2>/dev/null | tail -n +2 | while read -r line; do
    if echo "$line" | grep -qE "$PROC_PATTERN"; then
        crit "Processus avec motif de reverse shell/backdoor : $line"
    fi
done

# ===========================================================================
# RESUME FINAL
# ===========================================================================
section "RESUME"

echo -e "Critique  : ${C_RED}${CRIT_COUNT}${C_RST}"
echo -e "Attention : ${C_YEL}${WARN_COUNT}${C_RST}"
echo -e "Info      : ${C_CYA}${INFO_COUNT}${C_RST}"
echo ""
if [ "$CRIT_COUNT" -gt 0 ]; then
    echo -e "${C_RED}=> Des éléments CRITIQUES ont été trouvés. Investiguer en priorité.${C_RST}"
elif [ "$WARN_COUNT" -gt 0 ]; then
    echo -e "${C_YEL}=> Aucun élément critique évident, mais des points d'attention à vérifier manuellement.${C_RST}"
else
    echo -e "${C_GRN}=> Rien de suspect détecté par ce script. Cela ne garantit pas l'absence de compromission.${C_RST}"
fi
echo ""
echo "Rapport complet sauvegardé dans : $OUTFILE"
echo ""
echo "Rappel : ce script liste des INDICES, il ne confirme rien automatiquement."
echo "Chaque ligne [CRITIQUE] ou [ATTENTION] doit être vérifiée manuellement avant conclusion."
