"""Create a fresh backend-only encryption key without printing it or using shell interpolation.

Run once before storing any Feishu credentials. Re-running would invalidate existing
ciphertext and is intentionally refused when a local deployment marker exists.
"""
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile

root = Path(__file__).resolve().parent
marker = root / 'supabase' / '.temp' / 'encryption-configured.json'
if marker.exists():
    raise SystemExit('Already configured; refusing to rotate the encryption key.')
handle, name = tempfile.mkstemp(prefix='fa-encryption-', suffix='.env')
try:
    with os.fdopen(handle, 'w', encoding='utf-8') as stream:
        stream.write('FA_ENCRYPTION_KEY=' + base64.b64encode(secrets.token_bytes(32)).decode() + '\n')
    import shutil
    command = shutil.which('npx.cmd')
    if not command:
        raise SystemExit('npx.cmd not found')
    result = subprocess.run([command, '--yes', 'supabase@2.121.0', 'secrets', 'set', '--project-ref', 'dkjkcovxvsajdyfvltse', '--env-file', name], capture_output=True, text=True, encoding='utf-8', errors='replace', shell=False)
    if result.returncode:
        print('Backend encryption setup failed; no credential values displayed.')
        raise SystemExit(result.returncode)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({'configured': True}), encoding='utf-8')
    print('Backend encryption configured successfully; no key displayed.')
finally:
    Path(name).unlink(missing_ok=True)
