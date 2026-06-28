#!/usr/bin/env python3
"""HTMLをパスワードで暗号化し、ブラウザ内(Web Crypto)で復号する自己完結HTMLを出力する。

GitHub Pages は必ず公開されるため、保護はクライアント側暗号化で行う。
暗号文(AES-256-GCM)＋鍵導出(PBKDF2-HMAC-SHA256)を埋め込み、閲覧者がパスワードを
入力するとブラウザ内で復号して表示する。暗号文はパスワード無しでは復元不可能。

使い方:
    python3 scripts/encrypt_html.py 入力.html 出力.html "パスワード"
"""
import sys, os, base64, secrets, json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITER = 500_000  # PBKDF2反復回数（総当たり耐性。正規利用は1回だけ負担）

TEMPLATE = """<!DOCTYPE html>
<html lang="ja"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>__TITLE__</title>
<style>
 body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  font-family:-apple-system,"Hiragino Kaku Gothic ProN",Meiryo,sans-serif;
  background:linear-gradient(180deg,#0c0f22,#0f1226);color:#eef0ff}
 .box{background:#171a35;border:1px solid #2c3160;border-radius:16px;padding:30px 28px;width:340px;max-width:90vw;
  box-shadow:0 20px 60px rgba(0,0,0,.4);text-align:center}
 .lock{font-size:34px}
 h1{font-size:17px;margin:10px 0 4px}
 p{font-size:12.5px;color:#a8adda;margin:0 0 18px}
 input{width:100%;padding:11px 12px;border-radius:10px;border:1px solid #2c3160;background:#0f1226;color:#eef0ff;font-size:15px;box-sizing:border-box}
 input:focus{outline:none;border-color:#4f8cff}
 button{width:100%;margin-top:12px;padding:11px;border:none;border-radius:10px;background:#4f8cff;color:#fff;font-size:15px;font-weight:700;cursor:pointer}
 button:hover{background:#3f7cf0}
 .err{color:#ff8a8a;font-size:12.5px;margin-top:10px;min-height:16px}
 .foot{color:#5b6090;font-size:11px;margin-top:16px}
</style></head>
<body>
<div class="box" id="gate">
 <div class="lock">🔒</div>
 <h1>__TITLE__</h1>
 <p>このページはパスワードで保護されています</p>
 <form id="f">
   <input id="pw" type="password" placeholder="パスワードを入力" autocomplete="off" autofocus>
   <button type="submit">表示する</button>
 </form>
 <div class="err" id="err"></div>
 <div class="foot">ブラウザ内で復号されます（サーバーには送信されません）</div>
</div>
<script>
const DATA = __DATA__;
const STORAGE_KEY = "remolabo_mtg_pages_password";
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function decrypt(pw){
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    {name:"PBKDF2", salt:b64d(DATA.salt), iterations:DATA.iter, hash:"SHA-256"},
    baseKey, {name:"AES-GCM", length:256}, false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({name:"AES-GCM", iv:b64d(DATA.iv)}, key, b64d(DATA.ct));
  return new TextDecoder().decode(pt);
}
async function unlock(pw, remember){
  const html = await decrypt(pw);
  if (remember) sessionStorage.setItem(STORAGE_KEY, pw);
  document.open(); document.write(html); document.close();
}
document.getElementById("f").addEventListener("submit", async (e)=>{
  e.preventDefault();
  const err = document.getElementById("err");
  err.textContent = "復号中…";
  try{
    await unlock(document.getElementById("pw").value, true);
  }catch(_){ err.textContent = "パスワードが違います"; }
});
const saved = sessionStorage.getItem(STORAGE_KEY);
if (saved) {
  document.getElementById("err").textContent = "復号中…";
  unlock(saved, false).catch(() => {
    sessionStorage.removeItem(STORAGE_KEY);
    document.getElementById("err").textContent = "";
  });
}
</script>
</body></html>
"""

def main():
    if len(sys.argv) != 4:
        print(__doc__); sys.exit(1)
    src, dst, pw = sys.argv[1], sys.argv[2], sys.argv[3]
    plaintext = open(src, encoding="utf-8").read().encode("utf-8")
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER)
    key = kdf.derive(pw.encode("utf-8"))
    ct = AESGCM(key).encrypt(iv, plaintext, None)  # 末尾16byteにGCMタグを含む
    data = {
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ct": base64.b64encode(ct).decode(),
        "iter": ITER,
    }
    out = (TEMPLATE
           .replace("__TITLE__", "LINE自動回答 資料")
           .replace("__DATA__", json.dumps(data)))
    open(dst, "w", encoding="utf-8").write(out)
    print(f"✅ 暗号化完了: {dst}")
    print(f"   入力 {len(plaintext):,}B → 出力 {os.path.getsize(dst):,}B  / PBKDF2 {ITER:,}回 / AES-256-GCM")

if __name__ == "__main__":
    main()
