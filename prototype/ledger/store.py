# store.py: SQLite mein entries save/load karta hai, aur screenshots ko hash ke naam se rakhta hai. Sirf insert.
import hashlib
import sqlite3
from pathlib import Path

from .canon import sha256_hex

# table ka naksha. (run_id, n) unique hai, ek run mein do entries same number ki nahi.
SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    run_id TEXT    NOT NULL,
    n      INTEGER NOT NULL,
    time   INTEGER NOT NULL,
    url    TEXT    NOT NULL,
    action TEXT    NOT NULL,
    result TEXT    NOT NULL,
    shot   TEXT    NOT NULL,
    prev   TEXT    NOT NULL,
    hash   TEXT    NOT NULL,
    sig    TEXT    NOT NULL,
    PRIMARY KEY (run_id, n)
);
"""

COLUMNS = ("n", "time", "url", "action", "result", "shot", "prev", "hash", "sig")  # column order fix


class Store:
    def __init__(self, db_path, shots_dir):
        self.db = sqlite3.connect(db_path, check_same_thread=False)   # API ke threads se use ho sake (lock api.py mein)
        self.db.executescript(SCHEMA)          # table banao (agar nahi hai)
        self.shots = Path(shots_dir)           # screenshots ka folder
        self.shots.mkdir(parents=True, exist_ok=True)

    def save_shot(self, png_bytes: bytes) -> str:
        # screenshot ka hash naam, file pehle se ho to dobara nahi likhte
        h = sha256_hex(png_bytes)
        path = self.shots / f"{h}.png"
        if not path.exists():
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(png_bytes)   # pehle temp file mein likho
            tmp.replace(path)            # atomic rename: adhoori file final naam se nahi milegi
        return h

    def append(self, run_id: str, entry: dict) -> None:
        # entry insert karo, update ya delete nahi
        values = (run_id, *(entry[c] for c in COLUMNS))   # values ka tuple, order COLUMNS jaisa
        with self.db:                                     # transaction: poora ya kuch nahi
            self.db.execute(
                "INSERT INTO entries (run_id, n, time, url, action, result, "
                "shot, prev, hash, sig) VALUES (?,?,?,?,?,?,?,?,?,?)",   # ? = safe placeholder (SQL injection nahi)
                values,
            )

    def load(self, run_id: str) -> list[dict]:
        # is run ki entries step order mein, dict ki list ke roop mein
        rows = self.db.execute(
            f"SELECT {', '.join(COLUMNS)} FROM entries WHERE run_id=? ORDER BY n",
            (run_id,),
        ).fetchall()
        return [dict(zip(COLUMNS, r)) for r in rows]

    def close(self):
        self.db.close()   # connection band
