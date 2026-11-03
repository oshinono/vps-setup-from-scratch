#!/usr/bin/env bash
# VPS Hardening for Debian / Ubuntu
# Safe-by-default edition: backups, additive UFW rules, SSH validation, rollback.
# Run: sudo bash harden-gum.sh [--config FILE | --rollback [DIR] | --example-config | --dry-run]
set -Eeuo pipefail
umask 077

VERSION="2.1.0"
LOG="/var/log/harden-gum.log"
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a LOG

apt_get() { apt-get -o DPkg::Lock::Timeout=600 "$@"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
info() { printf '%s\n' "$*"; }

usage() {
  cat <<'USAGE'
VPS Hardening (Debian / Ubuntu)
  sudo bash harden-gum.sh                         интерактивный мастер
  sudo bash harden-gum.sh --config FILE           режим без вопросов
  sudo bash harden-gum.sh --dry-run --config FILE проверить конфиг и показать план
  sudo bash harden-gum.sh --rollback [DIR]        восстановить конфиги из бэкапа
  sudo bash harden-gum.sh --rollback DIR --yes    откат без подтверждения
  bash harden-gum.sh --example-config             пример конфига
  bash harden-gum.sh --help                       справка

Важно:
  * Перед SSH/UFW изменениями убедитесь, что у вас есть консоль VPS-провайдера.
  * Не закрывайте текущую SSH-сессию, пока не проверите новый вход во второй сессии.
  * --rollback восстанавливает файлы конфигурации, но не удаляет установленные пакеты
    и созданных пользователей, а также не отменяет уже выполненные обновления.
USAGE
}

print_example() {
  cat <<'EXAMPLE'
# harden.conf — передавайте только доверенный файл: он подключается через source.
COMPONENTS="updates autoupd user ssh ufw f2b sysctl time"
NEW_USER="admin"
SSH_PUBKEY="ssh-ed25519 AAAA... your-key" # замените на настоящий ключ (плейсхолдер невалиден)
GITHUB_USER=""                 # альтернативно: получить публичные ключи с GitHub
SSH_PORT=22
SSH_ALLOW_USERS="admin"        # список разрешённых SSH-пользователей
SSH_TCP_FORWARDING=0            # 1, если нужны SSH-туннели
EXTRA_PORTS="80 443"            # входящие TCP-порты UFW
DOCKER_PORTS=""                 # опубликованные TCP-порты Docker, разрешённые извне
F2B_IGNORE=""                   # доверенные IP/CIDR; пусто = без дополнительного whitelist
TIMEZONE_MODE="manual"          # manual — выбор из списка; ip — автоопределение по публичному IP
TIMEZONE="Europe/Berlin"        # используется только при TIMEZONE_MODE=manual
REBOOT_TIME="04:00"
SWAP_GB=2
SUDO_NOPASSWD=1                 # 1 — sudo без пароля (удобно для key-only учётки)
TG_TOKEN=""
TG_CHAT_ID=""
EXAMPLE
}

# ------------------------- argument parsing -------------------------
CONFIG="" ROLLBACK=0 ROLLBACK_DIR="" ASSUME_YES=0 DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--config) [[ -n "${2:-}" ]] || die "--config требует файл"; CONFIG=$2; shift 2 ;;
    --rollback) ROLLBACK=1; shift; if [[ -n "${1:-}" && "$1" != -* ]]; then ROLLBACK_DIR=$1; shift; fi ;;
    -y|--yes) ASSUME_YES=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --example-config) print_example; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "Неизвестный аргумент: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Запустите от root: sudo bash $0"
[[ -r /etc/os-release ]] || die "Не найден /etc/os-release"
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in debian|ubuntu) ;; *) die "Поддерживаются Debian и Ubuntu; обнаружено: ${PRETTY_NAME:-unknown}" ;; esac
command -v apt-get >/dev/null 2>&1 || die "Нужен apt-get"

mkdir -p /var/log
touch "$LOG"; chmod 600 "$LOG"
exec 9>/run/lock/harden-gum.lock
flock -n 9 || die "Другой экземпляр harden-gum уже запущен"

# ------------------------- defaults / state -------------------------
COMPONENTS=""
NEW_USER="" SSH_PUBKEY="" GITHUB_USER=""
SSH_PORT=22 SSH_ALLOW_USERS="" SSH_TCP_FORWARDING=0
OLD_SSH_PORT=22
EXTRA_PORTS="" DOCKER_PORTS=""
TIMEZONE_MODE="manual" TIMEZONE="Etc/UTC" REBOOT_TIME="04:00" SWAP_GB=2
SUDO_NOPASSWD=1
TG_TOKEN="" TG_CHAT_ID=""
_ssh_env="${SSH_CONNECTION:-${SSH_CLIENT:-}}"
MYIP="${_ssh_env%% *}"
# Prefer the actual local port of this SSH session; otherwise inspect ssh.socket / sshd.
_SESSION_SSH_PORT_FOUND=0
if [[ -n "${SSH_CONNECTION:-}" ]]; then
  _session_port=$(awk '{print $4}' <<< "$SSH_CONNECTION")
elif [[ -n "${SSH_CLIENT:-}" ]]; then
  _session_port=$(awk '{print $3}' <<< "$SSH_CLIENT")
else
  _session_port=""
fi
if [[ "$_session_port" =~ ^[0-9]{1,5}$ ]] && (( 10#$_session_port >= 1 && 10#$_session_port <= 65535 )); then
  OLD_SSH_PORT=$_session_port
  _SESSION_SSH_PORT_FOUND=1
fi
if (( _SESSION_SSH_PORT_FOUND == 0 )) && command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh.socket 2>/dev/null; then
  _socket_port=$(systemctl show ssh.socket -p Listen --value 2>/dev/null | grep -oE ':[0-9]{1,5}' | head -n1 | tr -d ':' || true)
  [[ "$_socket_port" =~ ^[0-9]{1,5}$ ]] && (( 10#$_socket_port >= 1 && 10#$_socket_port <= 65535 )) && OLD_SSH_PORT=$_socket_port
fi
if (( _SESSION_SSH_PORT_FOUND == 0 )) && [[ "$OLD_SSH_PORT" == 22 ]] && command -v sshd >/dev/null 2>&1; then
  _sshd_port=$(sshd -T 2>/dev/null | awk '$1=="port" {print $2; exit}' || true)
  [[ "$_sshd_port" =~ ^[0-9]{1,5}$ ]] && (( 10#$_sshd_port >= 1 && 10#$_sshd_port <= 65535 )) && OLD_SSH_PORT=$_sshd_port
fi
SSH_PORT=$OLD_SSH_PORT
F2B_IGNORE="$MYIP"
SEL=""
NONINT=0
[[ -n "$CONFIG" ]] && NONINT=1
(( ROLLBACK )) && (( ASSUME_YES )) && NONINT=1
if (( ! NONINT && ! ROLLBACK )); then
  [[ -t 0 && -t 1 ]] || die "Нужен интерактивный терминал или --config FILE"
fi

ORDER=(updates autoupd reboot user ssh ufw docker f2b sysctl time swap tg)
declare -A LABEL=(
  [updates]="Обновить систему"
  [autoupd]="Автообновления безопасности"
  [reboot]="Авто-перезагрузка после обновлений"
  [user]="Создать sudo-пользователя с SSH-ключом"
  [ssh]="Усилить SSH (отключить root и пароли)"
  [ufw]="Настроить UFW без сброса существующих правил"
  [docker]="Защитить опубликованные Docker-порты"
  [f2b]="Fail2ban (защита SSH от перебора)"
  [sysctl]="Безопасные сетевые параметры ядра"
  [time]="Часовой пояс и chrony"
  [swap]="Создать swap-файл"
  [tg]="Telegram-уведомления"
)
has() { [[ " $SEL " == *" $1 "* ]]; }

valid_user() { [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ && "$1" != root ]]; }
valid_port() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$1 <= 65535 )); }
valid_ports() {
  local p
  for p in $1; do valid_port "$p" || return 1; done
  return 0
}
valid_time() { [[ "$1" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]]; }
valid_timezone() {
  [[ "$1" =~ ^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$ ]] &&
    [[ -f "/usr/share/zoneinfo/$1" ]]
}
resolve_timezone_by_ip() {
  command -v curl >/dev/null 2>&1 || die "Для определения часового пояса по IP нужен curl"
  local detected
  detected=$(curl -fsS --connect-timeout 5 --max-time 12 https://ipapi.co/timezone/ 2>/dev/null | tr -d $'\r') ||
    die "Не удалось определить часовой пояс по публичному IP. Проверьте доступ к ipapi.co или выберите ручной режим."
  detected=${detected%%$'\n'*}
  valid_timezone "$detected" ||
    die "Сервис геолокации вернул некорректный часовой пояс: ${detected:-пустой ответ}"
  TIMEZONE=$detected
  info "Часовой пояс определён по публичному IP: $TIMEZONE"
}
valid_tg_token() { [[ "$1" =~ ^[0-9]{6,}:[A-Za-z0-9_-]{30,}$ ]]; }
valid_tg_chat() { [[ "$1" =~ ^-?[0-9]+$ || "$1" =~ ^@[A-Za-z0-9_]{5,}$ ]]; }
valid_key_line() {
  [[ "$1" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp[0-9]+|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)[[:space:]]+[A-Za-z0-9+/=]+([[:space:]].*)?$ ]]
}
filter_keys() {
  local line
  while IFS= read -r line; do
    line=${line%$'\r'}
    [[ -n "$line" ]] || continue
    if valid_key_line "$line"; then printf '%s\n' "$line"; fi
  done
}
validate_ip_list() {
  local value=$1
  [[ "$value" =~ ^[0-9a-fA-F:./[:space:]]*$ ]] || return 1
  [[ -z "$value" ]] && return 0
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$value" <<'PY'
import ipaddress, sys
for item in sys.argv[1].split():
    try:
        ipaddress.ip_network(item, strict=False)
    except ValueError:
        raise SystemExit(1)
PY
  else
    # Syntax validation is completed by fail2ban-client -t after installation.
    return 0
  fi
}

normalize_sel() {
  if has reboot && ! has autoupd; then SEL+="autoupd "; warn "reboot требует autoupd — компонент добавлен"; fi
  if has ssh && ! has user; then SEL+="user "; warn "ssh требует пользователя с ключом — user добавлен"; fi
  if has docker && ! has ufw; then SEL+="ufw "; warn "docker требует UFW — ufw добавлен"; fi
}

# ------------------------- Gum UI -------------------------
PINK=212 GREEN=42 RED=196 YELLOW=214
cancel() { printf '\nОтменено. Изменений не внесено.\n'; exit 0; }
title() { if (( NONINT )); then printf '\n== %s\n' "$1"; else gum style --bold --foreground "$PINK" "$1"; fi; }
note() { if (( NONINT )); then printf '[!] %s\n' "$1"; else gum style --foreground "$YELLOW" "! $1"; fi; }
okmsg() { if (( NONINT )); then printf '[ok] %s\n' "$1"; else gum style --foreground "$GREEN" "✔ $1"; fi; }
box() { if (( NONINT )); then printf '%s\n' "$1"; else gum style --border rounded --border-foreground "$PINK" --padding '1 2' "$1"; fi; }
ask() { gum input --header "$1" --value "${2:-}" --placeholder "${3:-}" --width 72 || cancel; }
install_gum() {
  command -v gum >/dev/null 2>&1 && return 0
  info "Устанавливаю gum..."
  apt_get update -qq
  apt_get install -y -qq curl gnupg ca-certificates
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://repo.charm.sh/apt/gpg.key | gpg --dearmor --yes -o /etc/apt/keyrings/charm.gpg
  chmod 0644 /etc/apt/keyrings/charm.gpg
  printf '%s\n' 'deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *' > /etc/apt/sources.list.d/charm.list
  apt_get update -qq
  apt_get install -y -qq gum || die "Не удалось установить gum; см. https://github.com/charmbracelet/gum"
}

# ------------------------- key and Telegram helpers -------------------------
tg_send() {
  local token=$1 chat=$2 message=$3
  curl -fsS -m 12 -K - --data-urlencode "chat_id=$chat" --data-urlencode "text=$message" >/dev/null 2>&1 \
    <<< "url = \"https://api.telegram.org/bot${token}/sendMessage\""
}

# ------------------------- configuration loading -------------------------
load_config() {
  [[ -r "$CONFIG" ]] || die "Не могу прочитать конфиг: $CONFIG"
  # Config is executable Bash. Use only a file you trust and own.
  # shellcheck disable=SC1090
  source "$CONFIG"
  SEL="${COMPONENTS:-} "
  [[ -n "${SEL// /}" ]] || die "В конфиге пустой COMPONENTS"
  local k raw
  for k in $SEL; do [[ -v LABEL[$k] ]] || die "Неизвестный компонент: $k"; done
  normalize_sel

  if has time; then
    case "$TIMEZONE_MODE" in
      ip) resolve_timezone_by_ip ;;
      manual) ;;
      *) die "TIMEZONE_MODE должен быть manual или ip" ;;
    esac
  fi

  if has user; then
    valid_user "$NEW_USER" || die "Неверный NEW_USER (root запрещён)"
    raw=${SSH_PUBKEY:-}
    if [[ -z "$raw" && -n "${GITHUB_USER:-}" ]]; then
      [[ "$GITHUB_USER" =~ ^[A-Za-z0-9-]{1,39}$ ]] || die "Неверный GITHUB_USER"
      if ! command -v curl >/dev/null 2>&1; then
        if (( DRY_RUN )); then die 'Для dry-run с GITHUB_USER нужен curl; установите его отдельно или задайте SSH_PUBKEY напрямую'; fi
        apt_get install -y -qq curl ca-certificates
      fi
      raw=$(curl -fsS --max-time 15 "https://github.com/${GITHUB_USER}.keys") || die "Не удалось получить ключи с GitHub"
    fi
    if [[ -z "$raw" && -s /root/.ssh/authorized_keys ]]; then
      raw=$(cat /root/.ssh/authorized_keys)
      note "SSH_PUBKEY пуст — использую ключи из /root/.ssh/authorized_keys"
    fi
    SSH_PUBKEY=$(filter_keys <<< "$raw")
    [[ -n "$SSH_PUBKEY" ]] || die "Нет SSH-ключей: задайте SSH_PUBKEY, GITHUB_USER или /root/.ssh/authorized_keys"
    if command -v ssh-keygen >/dev/null 2>&1; then
      local kt; kt=$(mktemp); printf '%s\n' "$SSH_PUBKEY" > "$kt"
      if ! ssh-keygen -lf "$kt" >/dev/null 2>&1; then rm -f "$kt"; die "ssh-keygen не распознал один или несколько SSH-ключей"; fi
      rm -f "$kt"
    fi
    SSH_PUBKEY+=$'\n'
  fi

  if has ssh || has ufw || has f2b; then valid_port "$SSH_PORT" || die "Неверный SSH_PORT"; fi
  if has ufw; then valid_ports "$EXTRA_PORTS" || die "Неверный EXTRA_PORTS"; fi
  if has docker; then valid_ports "$DOCKER_PORTS" || die "Неверный DOCKER_PORTS"; fi
  if has f2b; then validate_ip_list "$F2B_IGNORE" || die "Неверный F2B_IGNORE (используйте IPv4/IPv6 или CIDR)"; fi
  if has user; then [[ "$SUDO_NOPASSWD" == 0 || "$SUDO_NOPASSWD" == 1 ]] || die "SUDO_NOPASSWD должен быть 0 или 1"; fi
  if has reboot; then valid_time "$REBOOT_TIME" || die "Неверный REBOOT_TIME"; fi
  if has time; then
    command -v timedatectl >/dev/null 2>&1 || die "timedatectl недоступен"
    [[ "$TIMEZONE_MODE" == manual || "$TIMEZONE_MODE" == ip ]] || die "TIMEZONE_MODE должен быть manual или ip"
    valid_timezone "$TIMEZONE" || die "Часовой пояс не найден или имеет неверный формат: $TIMEZONE"
  fi
  if has swap; then
    [[ "$SWAP_GB" =~ ^[0-9]+$ ]] && (( SWAP_GB >= 1 && SWAP_GB <= 32 )) || die "SWAP_GB должен быть от 1 до 32"
  fi
  if has tg; then
    valid_tg_token "$TG_TOKEN" || die "Неверный TG_TOKEN"
    valid_tg_chat "$TG_CHAT_ID" || die "Неверный TG_CHAT_ID"
  fi
  if has ssh; then
    [[ "$SSH_TCP_FORWARDING" == 0 || "$SSH_TCP_FORWARDING" == 1 ]] || die "SSH_TCP_FORWARDING должен быть 0 или 1"
    [[ "$SUDO_NOPASSWD" == 0 || "$SUDO_NOPASSWD" == 1 ]] || die "SUDO_NOPASSWD должен быть 0 или 1"
    if [[ -z "$SSH_ALLOW_USERS" ]]; then SSH_ALLOW_USERS=$NEW_USER; fi
    local u found=0
    for u in $SSH_ALLOW_USERS; do
      valid_user "$u" || die "Недопустимое имя в SSH_ALLOW_USERS: $u"
      [[ "$u" == "$NEW_USER" ]] && found=1
    done
    (( found == 1 )) || die "SSH_ALLOW_USERS должен включать NEW_USER=$NEW_USER"
  fi
}

collect_interactive() {
  clear
  gum style --border double --border-foreground "$PINK" --foreground "$PINK" --bold --padding '1 4' --margin '1 0' \
    'VPS HARDENING' "Безопасная настройка Debian / Ubuntu · v${VERSION}"
  gum confirm 'Начать настройку?' --affirmative 'Поехали' --negative 'Выйти' || cancel

  local ram_mb k
  ram_mb=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
  local defaults=(updates autoupd user ssh ufw f2b sysctl time)
  if (( ram_mb <= 2048 )) && [[ -z "$(swapon --show --noheadings 2>/dev/null)" ]]; then defaults+=(swap); fi
  if command -v docker >/dev/null 2>&1 && systemctl is-active --quiet docker; then defaults+=(docker); fi
  local items=() selected=()
  for k in "${ORDER[@]}"; do
    items+=("${LABEL[$k]}")
    [[ " ${defaults[*]} " == *" $k "* ]] && selected+=("${LABEL[$k]}")
  done
  local chosen pre; pre=$(IFS=,; echo "${selected[*]}")
  title 'Что настроить?'
  chosen=$(gum choose --no-limit --height 16 --selected "$pre" "${items[@]}") || cancel
  for k in "${ORDER[@]}"; do grep -qxF "${LABEL[$k]}" <<< "$chosen" && SEL+="$k "; done
  [[ -n "${SEL// /}" ]] || cancel
  normalize_sel

  if has user; then
    title 'Пользователь и SSH-ключ'
    while :; do NEW_USER=$(ask 'Имя нового пользователя' 'admin'); valid_user "$NEW_USER" && break; note 'Недопустимое имя пользователя'; done
    local src raw clean gh
    while :; do
      local opts=()
      [[ -s /root/.ssh/authorized_keys ]] && opts+=('Ключи из /root/.ssh/authorized_keys')
      opts+=('Вставить публичный ключ' 'Скачать ключи с GitHub')
      src=$(gum choose "${opts[@]}") || cancel
      case "$src" in
        Ключи*) raw=$(cat /root/.ssh/authorized_keys) ;;
        Вставить*) raw=$(ask 'Публичный ключ' '' 'ssh-ed25519 AAAA... comment') ;;
        Скачать*) gh=$(ask 'Имя пользователя GitHub' '' 'octocat'); [[ "$gh" =~ ^[A-Za-z0-9-]{1,39}$ ]] || { note 'Имя GitHub некорректно'; continue; }; raw=$(curl -fsS --max-time 15 "https://github.com/${gh}.keys" 2>/dev/null || true) ;;
      esac
      clean=$(filter_keys <<< "$raw")
      if [[ -n "$clean" ]]; then SSH_PUBKEY="$clean"$'\n'; okmsg 'Формат публичного ключа принят; криптографическая проверка будет выполнена перед установкой'; break; fi
      note 'Не найден корректный публичный ключ; попробуйте ещё раз'
    done
    if id "$NEW_USER" >/dev/null 2>&1 && [[ "$(passwd -S "$NEW_USER" 2>/dev/null | awk '{print $2}')" == P ]]; then
      local sudo_choice; sudo_choice=$(gum choose 'sudo без пароля' 'sudo с существующим паролем') || cancel
      [[ "$sudo_choice" == 'sudo без пароля' ]] && SUDO_NOPASSWD=1 || SUDO_NOPASSWD=0
    else
      SUDO_NOPASSWD=1
      note 'Новый/безпарольный пользователь получит sudo без пароля. Парольный sudo можно включить после задания пароля вручную.'
    fi
  fi

  if has ssh || has ufw; then
    title 'SSH'
    while :; do SSH_PORT=$(ask 'SSH TCP-порт' "$SSH_PORT"); valid_port "$SSH_PORT" && break; note 'Порт должен быть числом 1–65535'; done
  fi
  if has ssh; then
    SSH_ALLOW_USERS=$NEW_USER
    note "По умолчанию SSH-вход будет разрешён только для $NEW_USER. Другие аккаунты добавьте в SSH_ALLOW_USERS в конфиге до запуска."
    local forwarding; forwarding=$(gum choose 'Запретить SSH TCP forwarding (рекомендуется)' 'Разрешить SSH TCP forwarding') || cancel
    [[ "$forwarding" == 'Разрешить SSH TCP forwarding' ]] && SSH_TCP_FORWARDING=1 || SSH_TCP_FORWARDING=0
  fi
  if has ufw; then
    title 'UFW'
    while :; do EXTRA_PORTS=$(ask 'Дополнительные входящие TCP-порты (через пробел)' '80 443'); valid_ports "$EXTRA_PORTS" && break; note 'Укажите номера портов через пробел'; done
  fi
  if has docker; then
    title 'Docker'
    note 'Новые внешние подключения к контейнерам будут запрещены, кроме перечисленных TCP-портов.'
    while :; do DOCKER_PORTS=$(ask 'Опубликованные TCP-порты Docker, доступные извне' ''); valid_ports "$DOCKER_PORTS" && break; note 'Укажите номера портов через пробел'; done
  fi
  if has f2b; then
    title 'Fail2ban'
    while :; do F2B_IGNORE=$(ask 'Белый список IP/CIDR (через пробел)' "$MYIP"); validate_ip_list "$F2B_IGNORE" && break; note 'Неверный IP/CIDR'; done
  fi
  if has reboot; then
    title 'Авто-перезагрузка'
    while :; do REBOOT_TIME=$(ask 'Время авто-перезагрузки (HH:MM)' '04:00'); valid_time "$REBOOT_TIME" && break; note 'Формат HH:MM'; done
  fi
  if has time; then
    title 'Часовой пояс'
    local tz_mode
    tz_mode=$(gum choose 'Автоматически определить по IP' 'Выбрать вручную из списка') || cancel
    if [[ "$tz_mode" == 'Автоматически определить по IP' ]]; then
      TIMEZONE_MODE=ip
      resolve_timezone_by_ip
    else
      TIMEZONE_MODE=manual
      TIMEZONE=$(timedatectl list-timezones | gum filter --placeholder 'Выберите часовой пояс...' --height 12) || cancel
      valid_timezone "$TIMEZONE" || die "Выбран некорректный часовой пояс: $TIMEZONE"
    fi
  fi
  if has swap; then
    if [[ -n "$(swapon --show --noheadings 2>/dev/null)" ]]; then note 'Swap уже активен — шаг будет пропущен'; SEL="${SEL//swap /}";
    else
      local free_gb; free_gb=$(df -BG --output=avail / | tail -n 1 | tr -dc '0-9')
      while :; do SWAP_GB=$(ask "Размер swap в ГБ (свободно: ${free_gb} ГБ)" '2'); [[ "$SWAP_GB" =~ ^[0-9]+$ ]] && (( SWAP_GB >= 1 && SWAP_GB <= 32 && SWAP_GB + 2 <= free_gb )) && break; note 'Нужно 1–32 ГБ и минимум 2 ГБ свободного места сверх swap'; done
    fi
  fi
  if has tg; then
    title 'Telegram'
    info 'Создайте бота через @BotFather, отправьте ему /start и узнайте chat_id.'
    while :; do
      TG_TOKEN=$(gum input --password --header 'Bot token' --placeholder '123456789:AA...' --width 72) || cancel
      valid_tg_token "$TG_TOKEN" || { note 'Токен выглядит некорректно'; continue; }
      TG_CHAT_ID=$(ask 'Chat ID или @канал' '')
      valid_tg_chat "$TG_CHAT_ID" || { note 'Некорректный chat ID'; continue; }
      if tg_send "$TG_TOKEN" "$TG_CHAT_ID" "Проверка Telegram от $(hostname)"; then okmsg 'Тестовое сообщение отправлено'; break; fi
      note 'Не удалось отправить тест; проверьте токен, chat_id и /start'
      local again; again=$(gum choose 'Повторить' 'Оставить Telegram без проверки' 'Отключить Telegram') || cancel
      [[ "$again" == 'Повторить' ]] && continue
      [[ "$again" == 'Отключить Telegram' ]] && { SEL="${SEL//tg /}"; TG_TOKEN=""; TG_CHAT_ID=""; }
      break
    done
  fi
}

# ------------------------- backup / rollback -------------------------
BK="/root/harden-backup-$(date +%Y%m%d-%H%M%S)-$$"
MANAGED_PATHS=(
  /etc/ssh/sshd_config.d/00-hardening.conf
  /etc/systemd/system/ssh.socket.d/10-hardening-port.conf
  /etc/fail2ban/jail.d/99-hardening.conf
  /etc/fail2ban/action.d/telegram-harden.conf
  /etc/sysctl.d/99-hardening.conf
  /etc/sysctl.d/99-swap.conf
  /etc/apt/apt.conf.d/99-hardening-auto-upgrades
  /etc/apt/apt.conf.d/99-hardening-reboot
  /etc/ufw
  /etc/default/ufw
  /etc/fstab
  /etc/pam.d/sshd
  /etc/harden-notify.conf
  /usr/local/bin/harden-notify
  /usr/local/bin/harden-ssh-login
  /usr/local/sbin/harden-docker-firewall
  /etc/harden-docker-firewall.conf
  /etc/systemd/system/harden-docker-firewall.service
  /etc/localtime
  /etc/timezone
)
USER_HOME=""
USER_EXISTED=0
USER_GROUPS_BEFORE=""
MANAGED_LIST=""
prepare_managed_paths() {
  local dhome
  USER_HOME=""
  USER_EXISTED=0
  USER_GROUPS_BEFORE=""
  if [[ -n "$NEW_USER" ]]; then
    if getent passwd "$NEW_USER" >/dev/null; then
      USER_EXISTED=1
      USER_HOME=$(getent passwd "$NEW_USER" | cut -d: -f6)
      USER_GROUPS_BEFORE=$(id -nG "$NEW_USER" 2>/dev/null || true)
    else
      dhome=$(awk -F= '$1 ~ /^[[:space:]]*DHOME[[:space:]]*$/ {gsub(/[[:space:]\"]/, "", $2); value=$2} END {print value}' /etc/adduser.conf 2>/dev/null || true)
      USER_HOME="${dhome:-/home}/${NEW_USER}"
    fi
    [[ -n "$USER_HOME" ]] || die "Не удалось определить домашний каталог $NEW_USER"
    MANAGED_PATHS+=("$USER_HOME/.ssh" "/etc/sudoers.d/90-${NEW_USER}")
  fi
  if has swap; then [[ -e /swapfile ]] || MANAGED_PATHS+=(/swapfile); fi
  MANAGED_LIST=$(printf '%s\n' "${MANAGED_PATHS[@]}")
}

step_backup() {
  install -d -m 0700 "$BK/files"
  : > "$BK/absent.list"
  local p target
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    if [[ -e "$p" || -L "$p" ]]; then
      target="$BK/files$p"
      mkdir -p "$(dirname "$target")"
      cp -a -- "$p" "$target"
    else
      printf '%s\n' "$p" >> "$BK/absent.list"
    fi
  done <<< "$MANAGED_LIST"
  printf '%s\n' "$SEL" > "$BK/components.txt"
  printf 'created=%s\n' "$(date -Is)" > "$BK/metadata.txt"
  : > "$BK/services.tsv"
  local unit load enabled active
  for unit in ssh.service sshd.service ssh.socket fail2ban.service chrony.service chronyd.service systemd-timesyncd.service apt-daily.timer apt-daily-upgrade.timer docker.service harden-docker-firewall.service; do
    load=$(systemctl show -p LoadState --value "$unit" 2>/dev/null || true); [[ -n "$load" ]] || load=not-found
    enabled=$(systemctl is-enabled "$unit" 2>/dev/null || true); [[ -n "$enabled" ]] || enabled=unknown
    active=$(systemctl is-active "$unit" 2>/dev/null || true); [[ -n "$active" ]] || active=unknown
    printf '%s\t%s\t%s\t%s\n' "$unit" "$load" "$enabled" "$active" >> "$BK/services.tsv"
  done
  printf '%s\t%s\t%s\n' "$NEW_USER" "$USER_EXISTED" "$USER_GROUPS_BEFORE" > "$BK/user.tsv"
  chmod -R go-rwx "$BK"
}

restore_path_from_backup() {
  local bk=$1 p=$2
  if grep -qxF "$p" "$bk/absent.list"; then
    rm -rf -- "$p"
  elif [[ -e "$bk/files$p" || -L "$bk/files$p" ]]; then
    mkdir -p "$(dirname "$p")"
    rm -rf -- "$p"
    cp -a -- "$bk/files$p" "$p"
  fi
}

do_rollback() {
  local bk=$1 p
  [[ "$bk" =~ ^/root/harden-backup-[^/]+$ && ! -L "$bk" ]] || die "Ожидается реальный каталог /root/harden-backup-*"
  [[ -d "$bk/files" && -f "$bk/absent.list" ]] || die "В $bk нет корректного бэкапа"
  info "Откат из $bk"
  if grep -qxF /etc/ufw "$bk/absent.list" && command -v ufw >/dev/null 2>&1; then ufw --force disable >/dev/null 2>&1 || true; fi
  if grep -qxF /usr/local/sbin/harden-docker-firewall "$bk/absent.list"; then
    local fwbin
    for fwbin in iptables ip6tables; do
      if command -v "$fwbin" >/dev/null 2>&1; then
        "$fwbin" -w 10 -D DOCKER-USER -j HARDEN-DOCKER >/dev/null 2>&1 || true
        "$fwbin" -w 10 -F HARDEN-DOCKER >/dev/null 2>&1 || true
        "$fwbin" -w 10 -X HARDEN-DOCKER >/dev/null 2>&1 || true
      fi
    done
  fi
  if grep -qxF /swapfile "$bk/absent.list"; then swapoff /swapfile >/dev/null 2>&1 || true; fi
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    case "$p" in
      /swapfile) rm -f /swapfile ;;
      *) rm -rf -- "$p" ;;
    esac
  done < "$bk/absent.list"
  cp -a "$bk/files/." /
  systemctl daemon-reload >/dev/null 2>&1 || true
  if [[ -f "$bk/services.tsv" ]]; then
    local unit load enabled active
    while IFS=$'\t' read -r unit load enabled active; do
      [[ -n "$unit" ]] || continue
      if [[ "$load" == not-found ]]; then
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
        continue
      fi
      case "$enabled" in
        enabled|enabled-runtime|linked|linked-runtime) systemctl enable "$unit" >/dev/null 2>&1 || true ;;
        disabled) systemctl disable "$unit" >/dev/null 2>&1 || true ;;
        masked|masked-runtime) systemctl mask "$unit" >/dev/null 2>&1 || true ;;
        *) : ;;
      esac
      case "$active" in
        active)
          case "$unit" in
            ssh.service|sshd.service|ssh.socket|fail2ban.service|chrony.service|chronyd.service|harden-docker-firewall.service)
              systemctl restart "$unit" >/dev/null 2>&1 || systemctl start "$unit" >/dev/null 2>&1 || true ;;
            *) systemctl start "$unit" >/dev/null 2>&1 || true ;;
          esac ;;
        inactive|failed) systemctl stop "$unit" >/dev/null 2>&1 || true ;;
        *) : ;;
      esac
    done < "$bk/services.tsv"
  fi
  if [[ -f "$bk/user.tsv" ]]; then
    local saved_user saved_existed saved_groups
    IFS=$'\t' read -r saved_user saved_existed saved_groups < "$bk/user.tsv" || true
    if [[ -n "$saved_user" ]] && id "$saved_user" >/dev/null 2>&1; then
      if [[ " $saved_groups " != *" sudo "* ]]; then gpasswd -d "$saved_user" sudo >/dev/null 2>&1 || true; fi
    fi
  fi
  if command -v sshd >/dev/null 2>&1 && ! sshd -t; then warn 'После отката sshd -t не прошёл; проверьте SSH вручную'; fi
  if command -v ufw >/dev/null 2>&1 && [[ -f /etc/ufw/ufw.conf ]]; then
    if grep -q '^ENABLED=yes' /etc/ufw/ufw.conf; then ufw --force enable >/dev/null 2>&1 || ufw reload || true
    else ufw --force disable >/dev/null 2>&1 || true; fi
  fi
  sysctl --system >/dev/null 2>&1 || true
  if [[ -s /etc/timezone ]]; then timedatectl set-timezone "$(cat /etc/timezone)" >/dev/null 2>&1 || true; fi
  info 'Конфигурационные файлы восстановлены.'
  info 'Пакеты, пользователи, пароли, обновления и внешние firewall/security groups не откатываются.'
}

if (( ROLLBACK )); then
  if [[ ( -z "$ROLLBACK_DIR" || $ASSUME_YES -eq 0 ) && ! -t 0 ]]; then
    die 'Для интерактивного отката нужен TTY; используйте --rollback DIR --yes'
  fi
  if [[ -z "$ROLLBACK_DIR" ]]; then
    mapfile -t backups < <(find /root -maxdepth 1 -mindepth 1 -type d -name 'harden-backup-*' -printf '%T@ %p\n' 2>/dev/null | sort -nr | cut -d' ' -f2-)
    ((${#backups[@]} > 0)) || die 'Бэкапы не найдены в /root'
    if command -v gum >/dev/null 2>&1 && [[ -t 0 ]]; then ROLLBACK_DIR=$(gum choose --header 'Выберите бэкап' "${backups[@]}") || cancel
    else
      info 'Доступные бэкапы:'; select ROLLBACK_DIR in "${backups[@]}"; do [[ -n "$ROLLBACK_DIR" ]] && break; done
    fi
  fi
  if (( ! ASSUME_YES )); then
    info "Будут восстановлены файлы из: $ROLLBACK_DIR"
    info 'Пользователи, пакеты, обновления и часовой пояс могут требовать отдельной ручной проверки.'
    if command -v gum >/dev/null 2>&1 && [[ -t 0 ]]; then gum confirm 'Продолжить откат?' || cancel
    else read -r -p 'Продолжить? [y/N] ' answer; [[ "$answer" == [yY] ]] || cancel; fi
  fi
  do_rollback "$ROLLBACK_DIR" 2>&1 | tee -a "$LOG"
  exit 0
fi

# ------------------------- component steps -------------------------
step_updates() {
  apt_get update -qq
  apt_get -y -qq -o Dpkg::Options::='--force-confold' upgrade
}

step_time() {
  timedatectl set-timezone "$TIMEZONE"
  # Avoid two competing NTP clients. Original unit state is captured in the backup.
  if systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
    systemctl disable --now systemd-timesyncd
  fi
  apt_get install -y -qq chrony
  systemctl enable --now chrony 2>/dev/null || systemctl enable --now chronyd
}

step_swap() {
  if [[ -n "$(swapon --show --noheadings 2>/dev/null)" ]]; then info 'Swap уже настроен — пропуск'; return 0; fi
  [[ ! -e /swapfile ]] || die '/swapfile уже существует, отказываюсь перезаписывать'
  local size_mb=$(( SWAP_GB * 1024 )) free_gb fs_type
  free_gb=$(df -BG --output=avail / | tail -n 1 | tr -dc '0-9')
  (( free_gb >= SWAP_GB + 2 )) || die "Недостаточно места для swap: нужно минимум $((SWAP_GB + 2)) ГБ свободно"
  fs_type=$(findmnt -n -o FSTYPE -T /)
  [[ "$fs_type" != btrfs ]] || die 'Автоматическое создание swap на Btrfs не поддерживается этим скриптом; настройте Btrfs swapfile вручную'
  if ! fallocate -l "${SWAP_GB}G" /swapfile 2>/dev/null; then
    dd if=/dev/zero of=/swapfile bs=1M count="$size_mb" status=none
  fi
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  if ! swapon /swapfile 2>/dev/null; then
    rm -f /swapfile
    dd if=/dev/zero of=/swapfile bs=1M count="$size_mb" status=none
    chmod 600 /swapfile; mkswap /swapfile >/dev/null; swapon /swapfile
  fi
  grep -qE '^/swapfile[[:space:]]' /etc/fstab || printf '%s\n' '/swapfile none swap sw 0 0' >> /etc/fstab
  printf '%s\n' 'vm.swappiness = 10' > /etc/sysctl.d/99-swap.conf
  sysctl -q -p /etc/sysctl.d/99-swap.conf
}

step_autoupd() {
  apt_get install -y -qq unattended-upgrades
  cat > /etc/apt/apt.conf.d/99-hardening-auto-upgrades <<'APTCONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APTCONF
  if [[ "${REBOOT_ON:-0}" == 1 ]]; then
    cat > /etc/apt/apt.conf.d/99-hardening-reboot <<EOF2
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "${REBOOT_TIME}";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
EOF2
  else
    rm -f /etc/apt/apt.conf.d/99-hardening-reboot
  fi
  systemctl enable --now apt-daily.timer apt-daily-upgrade.timer
}

step_user() {
  apt_get install -y -qq sudo openssh-client
  if ! id "$NEW_USER" >/dev/null 2>&1; then adduser --disabled-password --gecos '' "$NEW_USER"; fi
  usermod -aG sudo "$NEW_USER"
  local home group ak tmp key
  home=$(getent passwd "$NEW_USER" | cut -d: -f6)
  [[ -n "$home" && -d "$home" ]] || die "Не удалось определить домашний каталог $NEW_USER"
  group=$(id -gn "$NEW_USER")
  [[ ! -L "$home/.ssh" ]] || die "$home/.ssh является symlink; отказываюсь менять его"
  install -d -m 0700 -o "$NEW_USER" -g "$group" "$home/.ssh"
  ak="$home/.ssh/authorized_keys"
  [[ ! -L "$ak" ]] || die "$ak является symlink; отказываюсь менять его"
  touch "$ak"; chown "$NEW_USER:$group" "$ak"; chmod 0600 "$ak"
  tmp=$(mktemp)
  printf '%s\n' "$SSH_PUBKEY" > "$tmp"
  ssh-keygen -lf "$tmp" >/dev/null 2>&1 || { rm -f "$tmp"; die 'ssh-keygen не распознал один или несколько публичных ключей'; }
  while IFS= read -r key; do
    [[ -n "$key" ]] || continue
    grep -qxF -- "$key" "$ak" || printf '%s\n' "$key" >> "$ak"
  done < "$tmp"
  rm -f "$tmp"
  chown "$NEW_USER:$group" "$ak"; chmod 0600 "$ak"
  local sudo_file="/etc/sudoers.d/90-${NEW_USER}"
  if [[ "$SUDO_NOPASSWD" == 1 ]]; then printf '%s ALL=(ALL:ALL) NOPASSWD:ALL\n' "$NEW_USER" > "$sudo_file"
  else printf '%s ALL=(ALL:ALL) ALL\n' "$NEW_USER" > "$sudo_file"; fi
  chmod 0440 "$sudo_file"
  visudo -cf "$sudo_file" >/dev/null || { rm -f "$sudo_file"; die 'sudoers не прошёл visudo'; }
}


ufw_allow_ssh_port() {
  local port=$1 comment=$2 first
  first=$(ufw status numbered 2>/dev/null | grep -F "${port}/tcp" | head -n 1 || true)
  if [[ "$first" == *"ALLOW IN"* || "$first" == *"LIMIT IN"* ]]; then
    return 0
  elif [[ "$first" == *"DENY IN"* || "$first" == *"REJECT IN"* ]]; then
    die "В UFW уже есть правило DENY/REJECT для ${port}/tcp. Не буду перекрывать ограничение глобальным ALLOW; исправьте правило вручную и повторите."
  else
    ufw allow "${port}/tcp" comment "$comment" >/dev/null
  fi
}

step_ufw() {
  apt_get install -y -qq ufw
  if command -v ip >/dev/null 2>&1 && ip -6 addr show scope global 2>/dev/null | grep -q 'inet6 '; then
    if grep -qE '^[[:space:]]*IPV6=[Nn][Oo]' /etc/default/ufw 2>/dev/null; then
      sed -i 's/^[[:space:]]*IPV6=.*/IPV6=yes/' /etc/default/ufw
      warn 'На сервере есть глобальный IPv6; включена фильтрация IPv6 в UFW.'
    fi
  fi
  if command -v docker >/dev/null 2>&1 && [[ " ${SEL:-} " != *" docker "* ]]; then
    warn 'Docker установлен, но компонент docker не выбран: опубликованные Docker-порты могут обходить UFW.'
  fi
  # В отличие от ufw reset, правила не удаляются. Сначала открываем SSH.
  if ufw status | grep -q '^Status: active'; then
    warn 'Существующие allow-правила UFW останутся активными; проверьте их после настройки через ufw status numbered.'
  fi
  ufw_allow_ssh_port "$SSH_PORT" 'SSH hardening'
  if [[ "$SSH_PORT" != "$OLD_SSH_PORT" ]]; then
    ufw_allow_ssh_port "$OLD_SSH_PORT" 'SSH fallback - remove after testing'
    warn "Старый SSH-порт ${OLD_SSH_PORT} оставлен как временный запасной вход; удалите его только после проверки нового порта."
  fi
  local p
  for p in $EXTRA_PORTS; do ufw allow "${p}/tcp" comment 'Hardened service' >/dev/null; done
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  if ! ufw status | grep -q '^Status: active'; then ufw --force enable >/dev/null; else ufw reload >/dev/null; fi
  ufw status verbose
}

step_docker() {
  command -v docker >/dev/null 2>&1 || die 'Компонент docker выбран, но Docker CLI не установлен'
  systemctl is-active --quiet docker || die 'Docker daemon не запущен; сначала запустите Docker'
  command -v iptables >/dev/null 2>&1 || die 'iptables не найден'
  iptables -w 10 -S DOCKER-USER >/dev/null 2>&1 || die 'Цепочка DOCKER-USER не найдена. Нужен Docker с iptables backend; native nftables backend этим модулем не поддерживается.'
  if [[ -e /usr/local/sbin/harden-docker-firewall ]]; then
    local expected_helper_config
    expected_helper_config=$(printf 'DOCKER_TCP_PORTS=(%s)' "$DOCKER_PORTS")
    if grep -Fq 'This helper owns only the HARDEN-DOCKER chain' /usr/local/sbin/harden-docker-firewall && \
       [[ -f /etc/harden-docker-firewall.conf ]] && \
       [[ "$(cat /etc/harden-docker-firewall.conf)" == "$expected_helper_config" ]] && \
       systemctl is-active --quiet harden-docker-firewall.service; then
      # Re-run idempotent helper to restore rules if Docker restarted since last run.
      systemctl restart harden-docker-firewall.service || die 'Не удалось повторно применить Docker firewall'
      info 'Docker firewall уже настроен с этими портами и повторно применён'
      return 0
    fi
    die 'Скрипт-правила Docker уже существуют, но конфигурация отличается/служба неактивна. Сначала выполните rollback предыдущего бэкапа.'
  fi
  if iptables -w 10 -S HARDEN-DOCKER >/dev/null 2>&1; then
    die 'Цепочка HARDEN-DOCKER уже существует, но helper отсутствует; не буду перезаписывать неизвестные правила'
  fi
  local drivers
  drivers=$(docker network ls --format '{{.Driver}}' | sort -u)
  while IFS= read -r driver; do
    [[ -n "$driver" ]] || continue
    case "$driver" in bridge|host|null) ;; *) die "Docker network driver '$driver' не поддерживается этим firewall-модулем; не буду применять неполную фильтрацию" ;; esac
  done <<< "$drivers"

  cat > /etc/harden-docker-firewall.conf <<EOF2
DOCKER_TCP_PORTS=($DOCKER_PORTS)
EOF2
  cat > /usr/local/sbin/harden-docker-firewall <<'HELPER'
#!/usr/bin/env bash
set -Eeuo pipefail
# This helper owns only the HARDEN-DOCKER chain and its jump from DOCKER-USER.
. /etc/harden-docker-firewall.conf
apply_family() {
  local bin=$1 chain=HARDEN-DOCKER p line
  "$bin" -w 10 -S DOCKER-USER >/dev/null 2>&1 || return 2
  # Refuse to reorder unknown administrator rules in DOCKER-USER.
  while IFS= read -r line; do
    [[ "$line" == "-N DOCKER-USER" ]] && continue
    [[ "$line" == "-A DOCKER-USER -j RETURN" ]] && continue
    [[ "$line" == "-A DOCKER-USER -j HARDEN-DOCKER" ]] && continue
    echo "Custom rule in DOCKER-USER: $line; refusing to reorder it" >&2
    return 3
  done < <("$bin" -w 10 -S DOCKER-USER)
  "$bin" -w 10 -N "$chain" 2>/dev/null || true
  "$bin" -w 10 -F "$chain"
  "$bin" -w 10 -A "$chain" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  "$bin" -w 10 -A "$chain" -i docker+ -j RETURN
  "$bin" -w 10 -A "$chain" -i br+ -j RETURN
  for p in "${DOCKER_TCP_PORTS[@]}"; do
    [[ "$p" =~ ^[0-9]{1,5}$ ]] || { echo "Invalid TCP port in config: $p" >&2; return 4; }
    (( 10#$p >= 1 && 10#$p <= 65535 )) || return 4
    "$bin" -w 10 -A "$chain" -o docker+ -p tcp -m conntrack --ctstate NEW --ctorigdstport "$p" -j RETURN
    "$bin" -w 10 -A "$chain" -o br+ -p tcp -m conntrack --ctstate NEW --ctorigdstport "$p" -j RETURN
  done
  "$bin" -w 10 -A "$chain" -o docker+ -j DROP
  "$bin" -w 10 -A "$chain" -o br+ -j DROP
  "$bin" -w 10 -A "$chain" -j RETURN
  if ! "$bin" -w 10 -C DOCKER-USER -j "$chain" 2>/dev/null; then "$bin" -w 10 -I DOCKER-USER 1 -j "$chain"; fi
}
apply_family iptables
ipv6_docker_networks=0
if docker network ls -q 2>/dev/null | xargs -r docker network inspect --format '{{.EnableIPv6}}' 2>/dev/null | grep -qx true; then ipv6_docker_networks=1; fi
host_has_global_ipv6=0
if command -v ip >/dev/null 2>&1 && ip -6 addr show scope global 2>/dev/null | grep -q 'inet6 '; then host_has_global_ipv6=1; fi
if command -v ip6tables >/dev/null 2>&1 && ip6tables -S DOCKER-USER >/dev/null 2>&1; then
  apply_family ip6tables
elif (( ipv6_docker_networks == 1 || host_has_global_ipv6 == 1 )); then
  echo 'IPv6 is enabled but the Docker ip6tables DOCKER-USER chain is absent; refusing partial firewall protection' >&2
  exit 5
fi
HELPER
  chmod 0750 /usr/local/sbin/harden-docker-firewall
  cat > /etc/systemd/system/harden-docker-firewall.service <<'UNIT'
[Unit]
Description=Restrict inbound access to Docker-published ports
After=docker.service ufw.service
Requires=docker.service
PartOf=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/harden-docker-firewall

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now harden-docker-firewall.service
}

step_tg() {
  apt_get install -y -qq curl
  printf 'BOT_TOKEN=%q\nCHAT_ID=%q\n' "$TG_TOKEN" "$TG_CHAT_ID" > /etc/harden-notify.conf
  chmod 0600 /etc/harden-notify.conf
  cat > /usr/local/bin/harden-notify <<'NOTIFY'
#!/usr/bin/env bash
set -u
[[ -r /etc/harden-notify.conf ]] || exit 0
. /etc/harden-notify.conf
TEXT="[$(hostname)] ${1:-notification}"
curl -fsS -m 12 -K - --data-urlencode "chat_id=${CHAT_ID}" --data-urlencode "text=${TEXT}" >/dev/null 2>&1 \
  <<< "url = \"https://api.telegram.org/bot${BOT_TOKEN}/sendMessage\""
NOTIFY
  chmod 0750 /usr/local/bin/harden-notify
  cat > /usr/local/bin/harden-ssh-login <<'PAMHELPER'
#!/usr/bin/env bash
[[ "${PAM_TYPE:-}" == open_session && -n "${PAM_RHOST:-}" ]] || exit 0
/usr/local/bin/harden-notify "SSH login: ${PAM_USER:-unknown} from ${PAM_RHOST} at $(date '+%F %T %Z')" >/dev/null 2>&1 || true
exit 0
PAMHELPER
  chmod 0750 /usr/local/bin/harden-ssh-login
  [[ -f /etc/pam.d/sshd ]] || die '/etc/pam.d/sshd не найден'
  if ! grep -Fq 'harden-ssh-login' /etc/pam.d/sshd; then
    printf '%s\n' 'session optional pam_exec.so seteuid /usr/local/bin/harden-ssh-login' >> /etc/pam.d/sshd
  fi
  if ! /usr/local/bin/harden-notify 'Telegram-уведомления подключены: SSH-входы и fail2ban'; then
    warn 'Тестовое Telegram-сообщение не доставлено; конфигурация сохранена, проверьте токен и сетевой доступ вручную.'
  fi
}

step_ssh() {
  local cfg=/etc/ssh/sshd_config.d/00-hardening.conf
  local socket_cfg=/etc/systemd/system/ssh.socket.d/10-hardening-port.conf
  command -v sshd >/dev/null 2>&1 || apt_get install -y -qq openssh-server
  id "$NEW_USER" >/dev/null 2>&1 || die "Пользователь $NEW_USER не существует"
  local home
  home=$(getent passwd "$NEW_USER" | cut -d: -f6)
  local user_shell
  user_shell=$(getent passwd "$NEW_USER" | cut -d: -f7)
  [[ "$user_shell" != /usr/sbin/nologin && "$user_shell" != /sbin/nologin && "$user_shell" != /bin/false ]] || die "У $NEW_USER отключён shell: $user_shell"
  [[ -s "$home/.ssh/authorized_keys" ]] || die 'У нового пользователя отсутствует authorized_keys'
  install -d -m 0755 /etc/ssh/sshd_config.d

  restore_ssh_state() {
    restore_path_from_backup "$BK" "$cfg"
    restore_path_from_backup "$BK" "$socket_cfg"
    systemctl daemon-reload >/dev/null 2>&1 || true
    if systemctl is-active --quiet ssh.socket || systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
      systemctl restart ssh.socket >/dev/null 2>&1 || true
    fi
    systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true
  }

  # If UFW is already active, open the new port before restarting SSH.
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw_allow_ssh_port "$SSH_PORT" 'SSH hardening'
    if [[ "$SSH_PORT" != "$OLD_SSH_PORT" ]]; then ufw_allow_ssh_port "$OLD_SSH_PORT" 'SSH fallback - remove after testing'; fi
  fi

  local allow_line
  allow_line="$(printf '%s' "$SSH_ALLOW_USERS" | xargs)"
  local u
  for u in $allow_line; do
    if [[ "$u" != "$NEW_USER" ]]; then getent passwd "$u" >/dev/null || die "Пользователь из SSH_ALLOW_USERS не существует: $u"; fi
  done
  cat > "$cfg" <<EOF2
# Managed by harden-gum.sh. Keep this file first in sshd_config.d.
Port ${SSH_PORT}
EOF2
  # Keep the currently working port as a daemon-side fallback until a second login is tested.
  if [[ "$OLD_SSH_PORT" != "$SSH_PORT" ]]; then printf 'Port %s\n' "$OLD_SSH_PORT" >> "$cfg"; fi
  cat >> "$cfg" <<EOF2
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
AuthenticationMethods publickey
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding $( [[ "$SSH_TCP_FORWARDING" == 1 ]] && echo yes || echo no )
PermitTunnel no
AllowUsers ${allow_line}
EOF2

  # Validate syntax before touching the running daemon.
  if ! sshd -t; then
    restore_ssh_state
    die 'Новый SSH-конфиг не прошёл sshd -t; исходные файлы восстановлены'
  fi

  local socket_mode=0
  if systemctl is-active --quiet ssh.socket || systemctl is-enabled --quiet ssh.socket 2>/dev/null; then socket_mode=1; fi
  if (( socket_mode )); then
    # On socket-activated Ubuntu releases sshd_config Port does not control the listening socket.
    install -d -m 0755 "$(dirname "$socket_cfg")"
    cat > "$socket_cfg" <<EOF2
[Socket]
ListenStream=
ListenStream=${SSH_PORT}
EOF2
    if [[ "$OLD_SSH_PORT" != "$SSH_PORT" ]]; then printf 'ListenStream=%s\n' "$OLD_SSH_PORT" >> "$socket_cfg"; fi
    if ! systemctl daemon-reload || ! systemctl restart ssh.socket; then
      restore_ssh_state
      die 'Не удалось применить ssh.socket; исходные SSH-файлы восстановлены'
    fi
  else
    if ! (systemctl restart ssh 2>/dev/null || systemctl restart sshd); then
      restore_ssh_state
      die 'Не удалось перезапустить SSH; исходные SSH-файлы восстановлены'
    fi
  fi

  sleep 1
  local source_ip=${MYIP:-127.0.0.1} effective
  if ! effective=$(sshd -T -C "user=${NEW_USER},host=localhost,addr=${source_ip}" 2>/dev/null); then
    restore_ssh_state
    die 'Не удалось получить эффективную конфигурацию sshd; исходные файлы восстановлены'
  fi
  if ! grep -qi '^permitrootlogin no$' <<< "$effective" || \
     ! grep -qi '^passwordauthentication no$' <<< "$effective" || \
     ! grep -qi '^kbdinteractiveauthentication no$' <<< "$effective" || \
     ! grep -qi '^pubkeyauthentication yes$' <<< "$effective" || \
     ! grep -qi '^authenticationmethods publickey$' <<< "$effective" || \
     ! awk -v u="$NEW_USER" '
       tolower($1) == "allowusers" {
         for (i = 2; i <= NF; i++) {
           if ($i == u) found = 1
         }
       }
       END { exit !found }
     ' <<< "$effective"; then
    restore_ssh_state
    die 'Эффективные SSH-настройки не соответствуют ожиданиям; исходные файлы восстановлены'
  fi
  local authorized_keys_file
  authorized_keys_file=$(awk '$1 == "authorizedkeysfile" {print $2; exit}' <<< "$effective")
  if [[ "$authorized_keys_file" != ".ssh/authorized_keys" ]]; then
    restore_ssh_state
    die "SSH использует AuthorizedKeysFile '$authorized_keys_file', а скрипт подготовил ~/.ssh/authorized_keys; настройте путь вручную и повторите"
  fi

  if ! ss -ltnH 2>/dev/null | awk -v p="$SSH_PORT" '{ a=$4; sub(/^.*:/,"",a); if (a==p) found=1 } END { exit !found }'; then
    restore_ssh_state
    die "Порт ${SSH_PORT} не слушается; исходные SSH-файлы восстановлены"
  fi
  info "sshd проверен; порт ${SSH_PORT} слушается. Проверьте новый вход в отдельной сессии."
}

step_f2b() {
  apt_get install -y -qq fail2ban
  install -d -m 0755 /etc/fail2ban/action.d
  install -d -m 0755 /etc/fail2ban/jail.d
  if [[ -f /etc/fail2ban/jail.local ]]; then
    warn 'Найден /etc/fail2ban/jail.local: он может переопределять значения drop-in /etc/fail2ban/jail.d/99-hardening.conf.'
  fi
  cat > /etc/fail2ban/jail.d/99-hardening.conf <<EOF2
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd
ignoreip = 127.0.0.1/8 ::1 ${F2B_IGNORE}

[sshd]
enabled = true
port    = ${SSH_PORT}
EOF2
  if [[ "${TG:-0}" == 1 && -x /usr/local/bin/harden-notify ]]; then
    cat > /etc/fail2ban/action.d/telegram-harden.conf <<'ACTION'
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = /usr/local/bin/harden-notify "fail2ban: blocked <ip> (<name>), failures: <failures>" || true
actionunban =
ACTION
    cat >> /etc/fail2ban/jail.d/99-hardening.conf <<'JAIL'
action = %(action_)s
         telegram-harden
JAIL
  fi
  fail2ban-client -t
  systemctl enable --now fail2ban
  systemctl restart fail2ban
  fail2ban-client status sshd >/dev/null 2>&1 || die 'Fail2ban запущен, но jail sshd не активен; проверьте jail.local и jail.d'
}

step_sysctl() {
  cat > /etc/sysctl.d/99-hardening.conf <<'SYSCTL'
# Conservative network hardening. rp_filter=2 avoids strict-mode routing breakage.
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.log_martians = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
SYSCTL
  if [[ -d /proc/sys/net/ipv6/conf ]]; then
    cat >> /etc/sysctl.d/99-hardening.conf <<'SYSCTL6'
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
SYSCTL6
  fi
  sysctl -q -p /etc/sysctl.d/99-hardening.conf
}

# ------------------------- execution / reporting -------------------------
run_step() {
  local label=$1 fn=$2 rc=0
  printf '\n=== %s [%s]\n' "$label" "$(date -Is)" >> "$LOG"
  if (( NONINT )); then
    if bash -c "set -Eeuo pipefail; $fn" >> "$LOG" 2>&1; then rc=0; else rc=$?; fi
  else
    if gum spin --spinner dot --title "${label}..." -- bash -c "set -Eeuo pipefail; $fn >> '$LOG' 2>&1"; then rc=0; else rc=$?; fi
  fi
  if (( rc == 0 )); then okmsg "$label"; return 0; fi
  if (( NONINT )); then printf '[x] %s (код %s)\n' "$label" "$rc"; else gum style --foreground "$RED" "✘ $label (код $rc)"; fi
  printf '\nПоследние строки лога:\n'; tail -n 35 "$LOG"
  printf '\nКонфигурационный откат: bash %s --rollback %s\n' "$0" "$BK"
  exit "$rc"
}

audit_report() {
  printf '\n--- SYSTEM ---\n'; printf 'OS: %s\n' "${PRETTY_NAME:-unknown}"; printf 'Kernel: %s\n' "$(uname -r)"
  printf '\n--- SSH effective config ---\n'
  sshd -T 2>/dev/null | grep -E '^(port|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|allowusers|maxauthtries|allowtcpforwarding) ' || true
  printf '\n--- Listening ports ---\n'; ss -tulpnH 2>/dev/null | awk '{printf "%-5s %-30s %s\n",$1,$5,$7}'
  if command -v ufw >/dev/null 2>&1; then printf '\n--- UFW ---\n'; ufw status verbose 2>/dev/null | head -n 35 || true; fi
  if command -v fail2ban-client >/dev/null 2>&1; then printf '\n--- Fail2ban ---\n'; fail2ban-client status sshd 2>/dev/null | head -n 12 || true; fi
  if systemctl is-active --quiet harden-docker-firewall.service; then printf '\n--- Docker firewall ---\n'; iptables -w 10 -S DOCKER-USER 2>/dev/null || true; iptables -w 10 -S HARDEN-DOCKER 2>/dev/null || true; fi
  printf '\n--- TIME ---\n'; timedatectl 2>/dev/null | grep -E 'Time zone|synchronized|NTP service' || true
  if [[ -n "$(swapon --show --noheadings 2>/dev/null)" ]]; then printf '\n--- SWAP ---\n'; swapon --show; fi
  if [[ -f /var/run/reboot-required ]]; then printf '\nWARN: требуется перезагрузка после обновлений.\n'; fi
}

# Load settings before any system changes.
if (( NONINT )); then load_config; else install_gum; collect_interactive; fi

# Ensure normalized components and all dependencies are validated.
normalize_sel
prepare_managed_paths
if has user; then
  valid_user "$NEW_USER" || die 'Неверный NEW_USER'
  [[ -n "$SSH_PUBKEY" ]] || die 'Для user нужен SSH-ключ'
  if [[ "$SUDO_NOPASSWD" == 0 ]]; then
    id "$NEW_USER" >/dev/null 2>&1 || die 'SUDO_NOPASSWD=0 требует уже существующего пользователя с заданным паролем'
    [[ "$(passwd -S "$NEW_USER" 2>/dev/null | awk '{print $2}')" == P ]] || die 'SUDO_NOPASSWD=0 требует действующий пароль у NEW_USER'
  fi
fi
if has ssh; then
  [[ " $SSH_ALLOW_USERS " == *" $NEW_USER "* || -z "$SSH_ALLOW_USERS" ]] || die 'SSH_ALLOW_USERS должен включать NEW_USER'
  [[ -n "$SSH_ALLOW_USERS" ]] || SSH_ALLOW_USERS=$NEW_USER
  [[ " $SSH_ALLOW_USERS " == *" $NEW_USER "* ]] || die 'SSH_ALLOW_USERS должен содержать NEW_USER'
fi

SUMMARY="Компоненты: ${SEL//$'\n'/ }"$'\n'"Бэкап: $BK"$'\n'"Лог: $LOG"$'\n'
has ssh && SUMMARY+="SSH: порт ${SSH_PORT}; старый порт для fallback: ${OLD_SSH_PORT}; пользователи: ${SSH_ALLOW_USERS}"$'\n'
has ufw && SUMMARY+="UFW: SSH ${SSH_PORT}; дополнительные TCP-порты: ${EXTRA_PORTS:-нет}"$'\n'
has docker && SUMMARY+="Docker: разрешённые опубликованные TCP-порты: ${DOCKER_PORTS:-нет}"$'\n'
has reboot && SUMMARY+="Авто-перезагрузка: ${REBOOT_TIME}"$'\n'
has time && SUMMARY+="Часовой пояс: ${TIMEZONE} (режим: ${TIMEZONE_MODE})"$'\n'
has swap && SUMMARY+="Swap: ${SWAP_GB} ГБ (если ещё не настроен)"$'\n'
box "$SUMMARY"
if (( DRY_RUN )); then
  info 'DRY-RUN: конфигурация проверена; системные настройки не изменены (созданы только lock/log при запуске).'
  exit 0
fi
systemctl show -p Version >/dev/null 2>&1 || die 'Для применения настроек требуется работающий systemd (обычный Debian/Ubuntu VPS)'
if (( ! NONINT )); then gum confirm 'Создать резервную копию и применить изменения?' --affirmative 'Применить' --negative 'Отмена' || cancel; fi

REBOOT_ON=0; has reboot && REBOOT_ON=1
TG=0; has tg && TG=1
export -f die warn info apt_get ufw_allow_ssh_port step_backup step_updates step_time step_swap step_autoupd step_user step_ufw step_docker step_tg step_ssh step_f2b step_sysctl restore_path_from_backup
export BK MANAGED_LIST NEW_USER USER_HOME USER_EXISTED USER_GROUPS_BEFORE SSH_PUBKEY SSH_PORT OLD_SSH_PORT SSH_ALLOW_USERS SSH_TCP_FORWARDING SUDO_NOPASSWD EXTRA_PORTS DOCKER_PORTS TIMEZONE TIMEZONE_MODE REBOOT_TIME SWAP_GB REBOOT_ON TG TG_TOKEN TG_CHAT_ID F2B_IGNORE MYIP SEL

run_step 'Резервная копия конфигурации' step_backup
has updates && run_step 'Обновление системы' step_updates
has time && run_step 'Часовой пояс и chrony' step_time
has swap && run_step "Swap ${SWAP_GB} ГБ" step_swap
has autoupd && run_step 'Автообновления безопасности' step_autoupd
has user && run_step "Пользователь ${NEW_USER}" step_user
has ufw && run_step 'UFW (сохранение существующих правил)' step_ufw
has docker && run_step 'Docker firewall' step_docker
has tg && run_step 'Telegram-уведомления' step_tg
has ssh && run_step 'Усиление SSH с проверками' step_ssh
has f2b && run_step 'Fail2ban' step_f2b
has sysctl && run_step 'Сетевые параметры ядра' step_sysctl

printf '\nИТОГОВЫЙ ОТЧЁТ\n'
audit_report | tee "$BK/report.txt"
if has tg && [[ -x /usr/local/bin/harden-notify ]]; then
  /usr/local/bin/harden-notify "VPS hardening завершён. SSH: ${SSH_PORT}; backup: ${BK}" || true
fi

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
printf '\nГотово. Бэкап: %s\nОтчёт: %s/report.txt\nЛог: %s\n' "$BK" "$BK" "$LOG"
if has ssh; then
  printf '\nНЕ ЗАКРЫВАЙТЕ ТЕКУЩУЮ SSH-СЕССИЮ. В новом окне проверьте вход:\n  ssh -p %s %s@%s\n' "$SSH_PORT" "$NEW_USER" "${IP:-<IP-сервера>}"
  if [[ "$SSH_PORT" != "$OLD_SSH_PORT" ]]; then
    printf '\nСтарый SSH-порт %s оставлен слушающим как временный fallback. После успешного входа с нового порта повторно запустите этот же конфиг уже из новой SSH-сессии, чтобы переключить listener окончательно.\n' "$OLD_SSH_PORT"
    if has ufw; then printf 'После повторного запуска и проверки удалите старое правило UFW:\n  sudo ufw delete allow %s/tcp\n' "$OLD_SSH_PORT"; fi
  fi
fi
if has docker; then printf '\nDocker: проверьте публикацию контейнеров с внешнего хоста; разрешены только TCP-порты: %s\n' "${DOCKER_PORTS:-нет}"; fi
printf '\nОткат конфигураций: sudo bash %s --rollback %s\n' "$0" "$BK"
