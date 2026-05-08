#!/bin/bash

DB_PATH="/var/lib/soc_ai/events_ext_ueba.db"
LOCK_FILE="/var/lib/soc_ai/events_ext_ueba.lock" # Файл-замок
KEEP_ROWS=100000

if [ ! -f "$DB_PATH" ]; then
    echo "Error: Database file not found"
    exit 1
fi

# Используем flock: -x (эксклюзивная блокировка), -w 300 (ждать до 5 минут, если занято)
(
  flock -x -w 300 200 || { echo "Ошибка: База занята слишком долго"; exit 1; }

  LAST_ID=$(sqlite3 "$DB_PATH" "SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET $KEEP_ROWS;")

  if [ -z "$LAST_ID" ]; then
      echo "No pruning needed."
  else
      echo "Pruning database..."
      sqlite3 "$DB_PATH" "DELETE FROM events WHERE id <= $LAST_ID;"
      echo "Defragmenting (VACUUM)..."
      sqlite3 "$DB_PATH" "VACUUM;"
      echo "Done."
  fi
) 200>"$LOCK_FILE"
