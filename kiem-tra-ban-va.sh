#!/usr/bin/env bash
# Kiem tra ban va da duoc ghi de day du chua. Chay tu thu muc goc du an:
#   bash kiem-tra-ban-va.sh
set -u
ok=0; loi=0
kiem() {
  if grep -q "$2" "$1" 2>/dev/null; then
    echo "  [OK]  $3"; ok=$((ok+1))
  else
    echo "  [SAI] $3  -> chua ghi de $1"; loi=$((loi+1))
  fi
}
echo "Kiem tra 8 file ma nguon:"
kiem src/app/audit_chain.py "def reseal_unsealed"        "audit_chain.py  - ham va chuoi bam"
kiem src/app/audit_chain.py "unsealed_events"            "audit_chain.py  - bao cao ban ghi chua niem phong"
kiem src/app/demo_seed.py   "seal_event"                 "demo_seed.py    - niem phong su kien mau"
kiem src/app/security.py    "compact: bool = True"       "security.py     - rut gon otpauth URI"
kiem src/app/config.py      "session_absolute_hours"     "config.py       - tran tuyet doi phien"
kiem src/app/models.py      "root_issued_at"             "models.py       - cot moc phien goc"
kiem src/app/db.py          "root_issued_at"             "db.py           - nang cap schema"
kiem src/app/main.py        "api/auth/refresh"           "main.py         - endpoint gia han phien"
kiem src/app/gradio_ui.py   "_totp_qr_image"             "gradio_ui.py    - QR sac net"
kiem src/app/gradio_ui.py   "WARN_BEFORE_EXPIRY"         "gradio_ui.py    - tu dang xuat khi het han"
echo
echo "Kiem tra 3 file moi:"
for f in scripts/repair_audit_chain.py tests/test_fixes_2026_07.py \
         docs/BAN_VA_2026_07_28.md docker-compose.repair.yml; do
  if [ -f "$f" ]; then echo "  [OK]  $f"; ok=$((ok+1)); else echo "  [SAI] thieu $f"; loi=$((loi+1)); fi
done
echo
echo "Kiem tra cu phap Python:"
if python3 -m py_compile src/app/*.py scripts/repair_audit_chain.py 2>/dev/null; then
  echo "  [OK]  tat ca file compile duoc"; ok=$((ok+1))
else
  echo "  [SAI] co file loi cu phap"; loi=$((loi+1))
fi
echo
if [ "$loi" -eq 0 ]; then
  echo ">>> Day du ($ok muc). Buoc tiep theo:"
  echo "    Chay bang uv     : uv run python scripts/repair_audit_chain.py"
  echo "    Chay bang Docker : docker compose up -d --build   roi   \\"
  echo "                       docker compose -f docker-compose.yml \\"
  echo "                         -f docker-compose.repair.yml run --rm repair"
else
  echo ">>> Con $loi muc chua dung. Hay giai nen lai bang: unzip -o ban-va.zip"
fi
