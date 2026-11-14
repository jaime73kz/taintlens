import pytest

from conftest import ids

CASOS = [
    ("TL201", 'API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"'),
    ("TL201", 'password = "Hunter2Hunter2"'),
    ("TL201", 'AWS = "AKIAABCDEFGHIJKLMNOP"'),
    ("TL201", 'token = "ghp_' + "a" * 36 + '"'),
    ("TL201", 'x = "-----BEGIN RSA PRIVATE KEY-----"'),
    ("TL201", 'import requests\nrequests.post("u", auth=("a", "b"))\nconnect(password="a1b2c3d4e5")'),
    ("TL201", 'cfg = {"api_key": "a1b2c3d4e5f6g7h8"}'),
    ("TL202", 'import requests\nrequests.get("u", verify=False)'),
    ("TL202", 'import ssl\nc = ssl._create_unverified_context()'),
    ("TL202", 'import ssl\nc = ssl.create_default_context()\nc.check_hostname = False'),
    ("TL202", 'import ssl\nc = ssl.create_default_context()\nc.verify_mode = ssl.CERT_NONE'),
    ("TL203", 'from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)'),
    ("TL204", 'import jwt\njwt.decode(t, options={"verify_signature": False})'),
    ("TL204", 'import jwt\njwt.decode(t, k, algorithms=["none"])'),
    ("TL205", 'import hashlib\nhashlib.md5(b"x")'),
    ("TL205", 'import hashlib\nhashlib.sha1(b"x")'),
    ("TL205", 'import hashlib\nhashlib.new("md5")'),
    ("TL206", 'import yaml\nyaml.load(open("f"))'),
    ("TL207", 'import subprocess\ndef f(d):\n    subprocess.run("ls " + d, shell=True)'),
    ("TL208", 'import tempfile\nn = tempfile.mktemp()'),
    ("TL209", 'import os\nos.chmod("f", 0o777)'),
    ("TL209", 'import os\nos.chmod("f", 0o666)'),
    ("TL210", 'from transformers import AutoModel\nAutoModel.from_pretrained("m", trust_remote_code=True)'),
]


@pytest.mark.parametrize("regla,src", CASOS, ids=[f"{r}-{i}" for i, (r, _) in enumerate(CASOS)])
def test_regla_detecta(regla, src):
    assert regla in ids(src)


SEGUROS = [
    'API_KEY = os.environ["API_KEY"]',
    'password = "changeme"',
    'API_KEY = "your-api-key-here"',
    'token_type = "quoted-string"',
    'SECRET_FILE = "/run/secrets/key"',
    'password = ""',
    'import requests\nrequests.get("u")',
    'import requests\nrequests.get("u", verify=True)',
    'from flask import Flask\napp = Flask(__name__)\napp.run(debug=False)',
    'import hashlib\nhashlib.sha256(b"x")',
    'import hashlib\nhashlib.md5(b"x", usedforsecurity=False)',
    'import yaml\nyaml.load(open("f"), Loader=yaml.SafeLoader)',
    'import subprocess\nsubprocess.run("ls -l", shell=True)',
    'import os\nos.chmod("f", 0o600)',
    'import tempfile\nf = tempfile.mkstemp()',
    'import jwt\njwt.decode(t, k, algorithms=["HS256"])',
    'from transformers import AutoModel\nAutoModel.from_pretrained("m")',
]


@pytest.mark.parametrize("src", SEGUROS, ids=[f"seguro-{i}" for i in range(len(SEGUROS))])
def test_regla_no_alerta(src):
    assert not {i for i in ids(src) if i.startswith("TL2")}


def test_secreto_en_settings_debug():
    assert "TL203" in ids({"settings.py": "DEBUG = True\n"})
    assert "TL203" not in ids({"otro.py": "DEBUG = True\n"})


def test_tl206_no_duplica_tl107():
    r = ids("import yaml\nfrom flask import request\ndef h():\n    return yaml.load(request.data)\n")
    assert "TL107" in r and "TL206" not in r


def test_tl207_no_duplica_tl101():
    r = ids("import subprocess\nfrom flask import request\ndef h():\n    subprocess.run('ls ' + request.args['d'], shell=True)\n")
    assert "TL101" in r and "TL207" not in r


def test_un_secreto_no_se_cuenta_dos_veces():
    from conftest import hallazgos
    assert len([h for h in hallazgos('API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"') if h.regla == "TL201"]) == 1
