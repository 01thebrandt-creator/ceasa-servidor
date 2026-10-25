#!/bin/bash
# Cópia de segurança automática: o servidor guarda sozinho uma cópia por dia e mantém só as últimas BACKUP_KEEP.
# Prova: a cópia é criada com o servidor ligado, é um banco válido com os mesmos dados, e as antigas além do limite saem.
cd "$(dirname "$0")"
D=$(mktemp -d); PORT=8831; ok=0; tot=0
check() { tot=$((tot+1)); if [ "$2" = 1 ]; then ok=$((ok+1)); echo "OK    $1"; else echo "FALHA $1 | $3"; fi; }
mkdir -p "$D/copias"
for d in 01 02 03 04 05; do echo velho > "$D/copias/ceasa-2020-01-$d.db"; done
echo outro > "$D/copias/nao-mexer.txt"
PORT=$PORT HOST=127.0.0.1 DATA_DIR="$D" LOG_QUIET=1 AUTO_UPDATE=0 BACKUP_FIRST_S=2 BACKUP_KEEP=3 node server.js > "$D/log.txt" 2>&1 &
PID=$!
for i in $(seq 50); do curl -s "http://127.0.0.1:$PORT/api/health" >/dev/null && break; sleep 0.1; done
curl -s -X POST "http://127.0.0.1:$PORT/api/auth/signup" -H 'Content-Type: application/json' -d '{"email":"copia@teste.com","password":"senha123"}' >/dev/null
sleep 4
HOJE="$D/copias/ceasa-$(date -u +%F).db"
check "a cópia de hoje foi criada com o servidor ligado" "$([ -s "$HOJE" ] && echo 1)" "$(ls "$D/copias")"
N=$(node -e "const {DatabaseSync}=require('node:sqlite');const d=new DatabaseSync(process.argv[1],{readOnly:true});console.log(d.prepare('SELECT COUNT(*) n FROM users').get().n)" "$HOJE" 2>/dev/null)
check "a cópia é um banco válido e tem a conta criada" "$([ "$N" = 1 ] && echo 1)" "contas=$N"
NC=$(ls "$D/copias" | grep -cE '^ceasa-[0-9]{4}-[0-9]{2}-[0-9]{2}\.db$')
check "guarda só as últimas 3 cópias (as mais antigas saem)" "$([ "$NC" = 3 ] && echo 1)" "$(ls "$D/copias")"
check "a cópia de hoje e as duas mais recentes ficaram" "$([ -f "$D/copias/ceasa-2020-01-05.db" ] && [ -f "$D/copias/ceasa-2020-01-04.db" ] && [ ! -f "$D/copias/ceasa-2020-01-01.db" ] && echo 1)" "$(ls "$D/copias")"
check "arquivos que não são cópias não são tocados" "$([ -f "$D/copias/nao-mexer.txt" ] && echo 1)"
check "nenhum arquivo temporário sobrou" "$([ -z "$(ls "$D/copias" | grep '\.tmp$')" ] && echo 1)"
check "o servidor continua respondendo" "$(curl -s "http://127.0.0.1:$PORT/api/health" | grep -q '"ok":true' && echo 1)"
kill $PID; wait $PID 2>/dev/null
rm -rf "$D"
echo; echo "$ok/$tot verificações ok"; [ $ok = $tot ]
