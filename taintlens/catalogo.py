"""Catálogo de reglas, fuentes, sumideros y saneadores.

Todo está en tablas para que sea fácil de leer, ampliar y personalizar desde
un archivo `taintlens.toml`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .modelo import CLASES_INYECCION


# --------------------------------------------------------------------------
# Reglas
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Regla:
    id: str
    clase: str
    titulo: str
    cwe: str
    owasp: str
    severidad: str
    descripcion: str
    remedio: str
    malo: str
    bueno: str


def _r(*a) -> Regla:
    return Regla(*a)


REGLAS: dict[str, Regla] = {r.clase: r for r in [
    _r("TL101", "cmd", "Inyección de comandos del sistema", "CWE-78", "A03:2021 Inyección", "critica",
       "Un dato que controla el usuario llega a un comando que ejecuta el sistema operativo. "
       "Quien lo controle puede ejecutar cualquier comando con los permisos del programa.",
       "No construyas comandos con texto. Usa subprocess con una lista de argumentos y sin shell=True; "
       "si tienes que usar shell, escapa cada valor con shlex.quote y valida contra una lista permitida.",
       'os.system("ping " + host)',
       'subprocess.run(["ping", "-c", "1", host], check=True)'),
    _r("TL102", "cmd_arg", "Inyección de argumentos de comando", "CWE-88", "A03:2021 Inyección", "media",
       "Un dato no confiable se pasa como argumento de un programa externo. Sin shell no se pueden encadenar "
       "comandos, pero un valor como «--config=/etc/passwd» puede cambiar el comportamiento del programa.",
       "Valida el valor contra una lista permitida o un patrón estricto y añade «--» antes de los argumentos "
       "variables para que no se interpreten como opciones.",
       'subprocess.run(["git", "log", rama])',
       'subprocess.run(["git", "log", "--", rama])  # y valida rama antes'),
    _r("TL103", "code", "Inyección de código", "CWE-94", "A03:2021 Inyección", "critica",
       "Un dato no confiable se ejecuta como código Python (eval, exec, compile, imports dinámicos).",
       "Elimina el eval/exec. Para datos usa json.loads o ast.literal_eval; para elegir comportamiento "
       "usa un diccionario de funciones permitidas.",
       "resultado = eval(formula)",
       "resultado = ast.literal_eval(formula)  # solo literales"),
    _r("TL104", "sql", "Inyección SQL", "CWE-89", "A03:2021 Inyección", "critica",
       "Un dato no confiable forma parte del texto de una consulta SQL. Permite leer, modificar o borrar datos.",
       "Usa consultas parametrizadas: el texto de la consulta es fijo y los valores van aparte.",
       'cur.execute(f"SELECT * FROM users WHERE name = \'{nombre}\'")',
       'cur.execute("SELECT * FROM users WHERE name = ?", (nombre,))'),
    _r("TL105", "path", "Recorrido de rutas (path traversal)", "CWE-22", "A01:2021 Control de acceso", "alta",
       "Un dato no confiable decide la ruta de un archivo. Con «../» se puede leer o escribir fuera de la carpeta prevista.",
       "Usa solo el nombre del archivo (os.path.basename o secure_filename), resuelve la ruta final y comprueba "
       "que sigue dentro de la carpeta base con is_relative_to.",
       'open("/datos/" + nombre).read()',
       'ruta = (BASE / nombre).resolve()\nif not ruta.is_relative_to(BASE):\n    abort(403)\nruta.read_text()'),
    _r("TL106", "ssrf", "Falsificación de peticiones del servidor (SSRF)", "CWE-918", "A10:2021 SSRF", "alta",
       "Un dato no confiable decide la dirección a la que el servidor hace una petición. Se puede usar para llegar "
       "a servicios internos o a los metadatos de la nube.",
       "Valida el destino contra una lista de dominios permitidos y bloquea direcciones privadas y locales.",
       "requests.get(url_del_usuario)",
       'if urlparse(url).hostname not in PERMITIDOS:\n    abort(400)\nrequests.get(url)'),
    _r("TL107", "deser", "Deserialización insegura", "CWE-502", "A08:2021 Integridad", "critica",
       "Se deserializan datos no confiables con un formato que puede ejecutar código (pickle, yaml.load, torch.load, "
       "modelos con trust_remote_code).",
       "Usa formatos de solo datos (json, safetensors), yaml.safe_load, torch.load(..., weights_only=True) "
       "y nunca trust_remote_code=True con modelos que no controlas.",
       "pickle.loads(datos_recibidos)",
       "json.loads(datos_recibidos)"),
    _r("TL108", "xss", "Cross-site scripting (XSS)", "CWE-79", "A03:2021 Inyección", "media",
       "Un dato no confiable se escribe en una página HTML sin escapar. Quien lo controle puede ejecutar JavaScript "
       "en el navegador de otras personas.",
       "Escapa el dato con html.escape o usa plantillas con autoescape. No uses Markup ni mark_safe con datos de usuario.",
       'return "<h1>Hola " + nombre + "</h1>"',
       'return "<h1>Hola " + html.escape(nombre) + "</h1>"'),
    _r("TL109", "ssti", "Inyección de plantillas (SSTI)", "CWE-1336", "A03:2021 Inyección", "alta",
       "Un dato no confiable se usa como plantilla del motor de plantillas. Normalmente permite ejecutar código.",
       "Usa plantillas fijas y pasa los datos como variables de la plantilla.",
       "render_template_string(texto_usuario)",
       'render_template_string("Hola {{ nombre }}", nombre=nombre)'),
    _r("TL110", "redirect", "Redirección abierta", "CWE-601", "A01:2021 Control de acceso", "media",
       "Un dato no confiable decide a qué dirección se redirige al usuario. Se usa para phishing.",
       "Redirige solo a rutas relativas propias o a dominios de una lista permitida.",
       "return redirect(request.args['next'])",
       "return redirect(url_for(destino_permitido))"),
    _r("TL111", "xxe", "Entidades externas XML (XXE)", "CWE-611", "A05:2021 Configuración", "media",
       "Se procesa XML no confiable con un analizador que puede resolver entidades externas o expandir entidades "
       "sin límite.",
       "Usa defusedxml o desactiva la resolución de entidades y el acceso a la red.",
       "etree.fromstring(xml_usuario)",
       "defusedxml.ElementTree.fromstring(xml_usuario)"),
    _r("TL112", "regex", "Expresión regular controlada por el usuario (ReDoS)", "CWE-1333", "A05:2021 Configuración",
       "media",
       "Un dato no confiable se usa como expresión regular. Un patrón malicioso puede bloquear el programa.",
       "Escapa el dato con re.escape si solo es un texto a buscar o limita su longitud y usa un motor sin retroceso.",
       "re.search(patron_usuario, texto)",
       "re.search(re.escape(patron_usuario), texto)"),
    _r("TL113", "log", "Inyección en registros", "CWE-117", "A09:2021 Registro", "baja",
       "Un dato no confiable se escribe en el registro sin limpiar. Con saltos de línea se pueden falsificar entradas.",
       "Quita o escapa los saltos de línea antes de registrar y registra con parámetros, no con f-strings.",
       'logger.info(f"login de {usuario}")',
       'logger.info("login de %s", usuario.replace("\\n", " "))'),
    _r("TL114", "llm_prompt", "Entrada no confiable en el prompt de un modelo (inyección de instrucciones)",
       "CWE-1427", "OWASP LLM01 Inyección de prompts", "media",
       "Texto que controla un tercero (usuario, página web, correo) llega al prompt de un modelo de lenguaje. "
       "Puede contener instrucciones que el modelo obedezca.",
       "Separa las instrucciones de los datos, limita lo que el modelo puede hacer con herramientas y "
       "no des al modelo acceso a datos o acciones que el usuario no tendría.",
       "client.chat.completions.create(messages=[{'role': 'user', 'content': pagina_web}])",
       "# datos delimitados + permisos mínimos para las herramientas del modelo"),
    # --- reglas sin flujo de datos ---
    _r("TL201", "secreto", "Secreto escrito en el código", "CWE-798", "A07:2021 Identificación", "alta",
       "Hay una clave, contraseña o token escrito directamente en el código. Quien vea el repositorio lo tiene.",
       "Saca el secreto del código (variable de entorno o gestor de secretos), revócalo y crea uno nuevo.",
       'API_KEY = "sk-abc123..."',
       'API_KEY = os.environ["API_KEY"]'),
    _r("TL202", "tls", "Verificación de certificados desactivada", "CWE-295", "A02:2021 Criptografía", "media",
       "La conexión no comprueba el certificado del servidor, así que alguien en medio puede espiarla o alterarla.",
       "Deja la verificación activada y, si hace falta, indica el certificado de confianza correcto.",
       "requests.get(url, verify=False)",
       "requests.get(url)"),
    _r("TL203", "debug", "Modo depuración activado", "CWE-489", "A05:2021 Configuración", "media",
       "El servidor se arranca con el modo debug, que en muchos frameworks permite ejecutar código desde el navegador.",
       "No actives debug fuera de tu equipo; lee el valor de una variable de entorno.",
       "app.run(debug=True)",
       'app.run(debug=os.environ.get("DEBUG") == "1")'),
    _r("TL204", "jwt", "Firma de token JWT sin comprobar", "CWE-347", "A07:2021 Identificación", "alta",
       "Se decodifica un token JWT sin verificar su firma, así que cualquiera puede fabricar tokens.",
       "Verifica siempre la firma y fija el algoritmo permitido.",
       'jwt.decode(token, options={"verify_signature": False})',
       'jwt.decode(token, clave, algorithms=["HS256"])'),
    _r("TL205", "hash", "Hash criptográfico débil", "CWE-327", "A02:2021 Criptografía", "baja",
       "MD5 y SHA-1 están rotos para usos de seguridad.",
       "Usa SHA-256 o superior; para contraseñas usa bcrypt, scrypt o argon2.",
       "hashlib.md5(contraseña.encode())",
       "hashlib.sha256(datos).hexdigest()  # contraseñas: argon2 / bcrypt"),
    _r("TL206", "yaml_inseguro", "yaml.load sin cargador seguro", "CWE-502", "A08:2021 Integridad", "media",
       "yaml.load sin indicar un cargador seguro puede construir objetos de Python arbitrarios.",
       "Usa yaml.safe_load.",
       "yaml.load(texto)",
       "yaml.safe_load(texto)"),
    _r("TL207", "shell_true", "shell=True con un comando que no es fijo", "CWE-78", "A03:2021 Inyección", "baja",
       "Se usa shell=True con un comando que se construye en tiempo de ejecución. Hoy no recibe datos de usuario, "
       "pero es muy fácil que acabe recibiéndolos.",
       "Pasa una lista de argumentos y quita shell=True.",
       'subprocess.run("ls " + carpeta, shell=True)',
       'subprocess.run(["ls", carpeta])'),
    _r("TL208", "tmp", "Archivo temporal con nombre predecible", "CWE-377", "A05:2021 Configuración", "baja",
       "tempfile.mktemp devuelve un nombre sin crear el archivo, así que otro programa puede adelantarse.",
       "Usa tempfile.mkstemp o NamedTemporaryFile.",
       "nombre = tempfile.mktemp()",
       "fd, nombre = tempfile.mkstemp()"),
    _r("TL209", "permisos", "Permisos de archivo demasiado abiertos", "CWE-732", "A01:2021 Control de acceso",
       "media",
       "Se da permiso de escritura a todo el mundo sobre un archivo o carpeta.",
       "Da solo los permisos necesarios, por ejemplo 0o600 o 0o640.",
       "os.chmod(ruta, 0o777)",
       "os.chmod(ruta, 0o600)"),
    _r("TL210", "codigo_remoto", "trust_remote_code=True", "CWE-829", "OWASP LLM03 Cadena de suministro", "media",
       "Cargar un modelo con trust_remote_code=True ejecuta código que viene dentro del repositorio del modelo.",
       "Revisa y fija la versión del repositorio (revision=) o desactiva trust_remote_code.",
       'AutoModel.from_pretrained(nombre, trust_remote_code=True)',
       'AutoModel.from_pretrained(nombre, revision="<commit revisado>")'),
]}

SIN_FLUJO = {"secreto", "tls", "debug", "jwt", "hash", "yaml_inseguro", "shell_true", "tmp", "permisos",
             "codigo_remoto"}


def regla_de(clase: str) -> Regla:
    return REGLAS[clase]


# --------------------------------------------------------------------------
# Fuentes
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Fuente:
    tipo: str
    nombres: tuple = ()
    colas: tuple = ()
    modo: str = "llamada"       # "objeto": la propia referencia está contaminada
    recv_re: str = ""
    opcional: str = ""          # "archivo": solo con fuentes_archivo


_REQ = ("get", "post", "put", "delete", "head", "patch", "options", "request")

FUENTES: list[Fuente] = [
    # entrada web (objetos)
    Fuente("http", ("flask.request", "flask.globals.request", "bottle.request", "quart.request",
                    "sanic.request", "falcon.Request", "starlette.requests.Request",
                    "django.http.HttpRequest", "fastapi.Request"), modo="objeto"),
    Fuente("argv", ("sys.argv",), modo="objeto"),
    Fuente("entorno", ("os.environ", "os.environb"), modo="objeto"),
    Fuente("stdin", ("sys.stdin",), modo="objeto"),
    # llamadas
    Fuente("stdin", ("input", "builtins.input", "getpass.getpass", "fileinput.input")),
    Fuente("entorno", ("os.getenv", "os.getenvb")),
    Fuente("argv", colas=("parse_args", "parse_known_args")),
    Fuente("red", tuple(f"requests.{m}" for m in _REQ) + tuple(f"httpx.{m}" for m in _REQ)
           + ("urllib.request.urlopen", "urllib3.request", "aiohttp.request")),
    Fuente("red", colas=("recv", "recvfrom", "recv_into"), recv_re=r"(sock|conn|client|s)$"),
    Fuente("http", ("streamlit.text_input", "streamlit.text_area", "streamlit.chat_input",
                    "streamlit.file_uploader", "streamlit.selectbox", "gradio.Textbox")),
    # salida de modelos de lenguaje
    Fuente("llm", ("openai.ChatCompletion.create", "openai.Completion.create", "litellm.completion",
                   "ollama.chat", "ollama.generate", "cohere.chat", "mistralai.chat"),
           colas=("chat.completions.create", "responses.create", "messages.create", "completions.create",
                  "generate_content", "generate_text", "chat.send_message")),
    Fuente("llm", colas=("invoke", "predict", "ainvoke", "generate"),
           recv_re=r"(llm|chat|model|gpt|claude|agent|chain|gemini|mistral|assistant)"),
    # archivos (solo si se activan)
    Fuente("archivo", ("open", "io.open", "codecs.open", "pandas.read_csv", "pandas.read_json",
                       "pandas.read_excel", "json.load"), opcional="archivo"),
    Fuente("archivo", colas=("read_text", "read_bytes"), opcional="archivo"),
]

# Decoradores que marcan una función como punto de entrada y de dónde vienen sus parámetros.
DECORADORES_ENTRADA = {
    "route": "http", "get": "http", "post": "http", "put": "http", "delete": "http", "patch": "http",
    "head": "http", "options": "http", "websocket": "http", "api_route": "http", "on_message": "http",
    "command": "argv", "callback": "argv",
    "tool": "llm", "call_tool": "llm", "mcp_tool": "llm", "function_tool": "llm", "kernel_function": "llm", "tool_plain": "llm",
}
NOMBRES_ENTRADA = {"lambda_handler": "http"}
FRAMEWORKS_WEB = ("flask", "django", "fastapi", "starlette", "aiohttp", "bottle", "tornado", "sanic",
                  "quart", "falcon", "streamlit", "chainlit", "gradio")


# --------------------------------------------------------------------------
# Sumideros
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Sumidero:
    clase: str
    nombres: tuple = ()
    colas: tuple = ()
    args: tuple = (0,)          # posiciones; "*" = todas
    kws: tuple = ()
    receptor: bool = False
    cond: str = ""
    recv_re: str = ""
    confianza: str = "alta"
    etiqueta: str = ""


_OS_EXEC = tuple(f"os.{n}" for n in ("execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp",
                                      "execvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv",
                                      "spawnve", "spawnvp", "spawnvpe", "startfile"))
_SUBPROC = tuple(f"subprocess.{n}" for n in ("run", "call", "check_call", "check_output", "Popen"))
_OS_FS = ("os.remove", "os.unlink", "os.rmdir", "os.removedirs", "os.mkdir", "os.makedirs", "os.listdir",
          "os.scandir", "os.walk", "os.chdir", "os.chmod", "os.chown", "os.truncate", "os.open")
_LOGM = ("debug", "info", "warning", "warn", "error", "critical", "exception", "log")

SUMIDEROS: list[Sumidero] = [
    Sumidero("cmd", ("os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput",
                     "commands.getoutput", "asyncio.create_subprocess_shell", "pty.spawn", "pexpect.spawn",
                     "pexpect.run", "os.popen2", "os.popen3") + _OS_EXEC,
             kws=("command", "cmd"), etiqueta="comando del sistema"),
    Sumidero("cmd", colas=("exec_command",), kws=("command",), confianza="media", recv_re=r"(ssh|client|conn)",
             etiqueta="ejecución remota"),
    Sumidero("cmd", _SUBPROC, args=(0,), kws=("args",), cond="subprocess", etiqueta="subprocess"),
    Sumidero("cmd_arg", ("asyncio.create_subprocess_exec",), args=("*",), etiqueta="subprocess"),
    Sumidero("code", ("eval", "exec", "compile", "builtins.eval", "builtins.exec", "__import__",
                      "importlib.import_module", "importlib.__import__", "runpy.run_path", "runpy.run_module",
                      "pandas.eval", "code.interact"), etiqueta="evaluación de código"),
    Sumidero("sql", ("sqlalchemy.text", "sqlalchemy.sql.text", "pandas.read_sql", "pandas.read_sql_query",
                     "django.db.models.expressions.RawSQL", "RawSQL"),
             kws=("sql", "query", "statement"), etiqueta="consulta SQL"),
    Sumidero("sql", colas=("execute", "executemany", "executescript", "exec_driver_sql", "raw"),
             kws=("sql", "query", "operation", "statement"), confianza="media", etiqueta="consulta SQL"),
    Sumidero("path", ("open", "io.open", "codecs.open", "os.remove", "os.unlink", "os.rmdir", "os.removedirs",
                      "os.mkdir", "os.makedirs", "os.listdir", "os.scandir", "os.walk", "os.chdir", "os.chmod",
                      "os.chown", "os.truncate", "os.open", "shutil.rmtree", "shutil.make_archive",
                      "flask.send_file", "fastapi.responses.FileResponse", "starlette.responses.FileResponse",
                      "tarfile.open", "zipfile.ZipFile", "pandas.read_csv", "pandas.read_excel",
                      "pandas.read_json", "pandas.read_parquet", "PIL.Image.open", "cv2.imread",
                      "flask.send_from_directory", "send_file", "FileResponse"),
             args=(0,), kws=("file", "path", "filename", "filepath", "fname", "directory", "path_or_buf"),
             etiqueta="acceso a archivo"),
    Sumidero("path", ("os.rename", "os.replace", "os.symlink", "os.link", "shutil.copy", "shutil.copy2",
                      "shutil.copyfile", "shutil.copytree", "shutil.move"),
             args=(0, 1), kws=("src", "dst"), etiqueta="acceso a archivo"),
    Sumidero("path", colas=("read_text", "read_bytes", "unlink", "rmdir", "touch", "mkdir", "extractall",
                            "extract", "write_text", "write_bytes"),
             args=(), receptor=True, confianza="media", etiqueta="acceso a archivo"),
    Sumidero("ssrf", tuple(f"requests.{m}" for m in _REQ if m != "request")
             + tuple(f"httpx.{m}" for m in _REQ if m != "request")
             + ("urllib.request.urlopen", "urllib.request.urlretrieve", "urllib.request.Request",
                "socket.create_connection", "aiohttp.request", "urllib3.request", "http.client.HTTPConnection",
                "http.client.HTTPSConnection", "webbrowser.open"),
             kws=("url", "uri", "address"), etiqueta="petición HTTP"),
    Sumidero("ssrf", ("requests.request", "httpx.request"), args=(1,), kws=("url",), etiqueta="petición HTTP"),
    Sumidero("ssrf", colas=("get", "post", "put", "delete", "head", "patch", "request", "stream"),
             kws=("url",), recv_re=r"(client|http|req_?session|sess)$", confianza="media",
             etiqueta="petición HTTP"),
    Sumidero("deser", ("pickle.load", "pickle.loads", "pickle.Unpickler", "cPickle.load", "cPickle.loads",
                       "_pickle.load", "_pickle.loads", "marshal.load", "marshal.loads", "shelve.open",
                       "dill.load", "dill.loads", "cloudpickle.load", "cloudpickle.loads", "jsonpickle.decode",
                       "joblib.load", "pandas.read_pickle", "yaml.unsafe_load", "yaml.unsafe_load_all"),
             kws=("file", "data", "stream", "filename", "path"), etiqueta="deserialización"),
    Sumidero("deser", ("yaml.load", "yaml.load_all"), kws=("stream",), cond="sin_cargador_seguro",
             etiqueta="yaml.load"),
    Sumidero("deser", ("torch.load",), kws=("f",), cond="sin_weights_only", etiqueta="torch.load"),
    Sumidero("deser", ("numpy.load",), kws=("file",), cond="allow_pickle", etiqueta="numpy.load"),
    Sumidero("deser", colas=("from_pretrained",), kws=("pretrained_model_name_or_path", "model"),
             cond="trust_remote_code", confianza="media", etiqueta="carga de modelo con código remoto"),
    Sumidero("deser", ("transformers.pipeline",), kws=("model",), cond="trust_remote_code",
             etiqueta="carga de modelo con código remoto"),
    Sumidero("ssti", ("flask.render_template_string", "render_template_string", "jinja2.Template",
                      "mako.template.Template", "tornado.template.Template", "django.template.Template"),
             kws=("source", "template"), etiqueta="plantilla"),
    Sumidero("ssti", colas=("from_string",), kws=("source",), confianza="media", etiqueta="plantilla"),
    Sumidero("xss", ("flask.Markup", "markupsafe.Markup", "django.utils.safestring.mark_safe", "mark_safe",
                     "django.http.HttpResponse", "django.http.HttpResponseBadRequest",
                     "fastapi.responses.HTMLResponse", "starlette.responses.HTMLResponse", "flask.make_response",
                     "Markup", "HttpResponse", "HTMLResponse"),
             kws=("content",), etiqueta="HTML sin escapar"),
    Sumidero("redirect", ("flask.redirect", "django.shortcuts.redirect", "django.http.HttpResponseRedirect",
                          "django.http.HttpResponsePermanentRedirect", "fastapi.responses.RedirectResponse",
                          "starlette.responses.RedirectResponse", "werkzeug.utils.redirect", "redirect",
                          "RedirectResponse", "HttpResponseRedirect"),
             kws=("location", "url"), etiqueta="redirección"),
    Sumidero("xxe", ("lxml.etree.fromstring", "lxml.etree.parse", "lxml.etree.XML", "lxml.etree.HTML",
                     "xml.dom.minidom.parseString", "xml.dom.minidom.parse", "xml.sax.parseString",
                     "xml.sax.parse", "xml.etree.ElementTree.fromstring", "xml.etree.ElementTree.parse",
                     "xml.etree.ElementTree.XML", "xml.dom.pulldom.parseString", "xml.dom.expatbuilder.parseString"),
             kws=("text", "source"), etiqueta="análisis de XML"),
    Sumidero("regex", ("re.compile", "re.match", "re.search", "re.fullmatch", "re.findall", "re.finditer",
                       "re.sub", "re.subn", "re.split", "regex.compile", "regex.search", "regex.match"),
             kws=("pattern",), etiqueta="expresión regular"),
    Sumidero("log", tuple(f"logging.{m}" for m in _LOGM), args=("*",), etiqueta="registro"),
    Sumidero("log", colas=_LOGM, args=("*",), recv_re=r"(log|logger|logging)$", confianza="media",
             etiqueta="registro"),
    Sumidero("llm_prompt", ("openai.ChatCompletion.create", "openai.Completion.create", "litellm.completion",
                            "ollama.chat", "ollama.generate"),
             args=("*",), kws=("messages", "prompt", "input", "contents", "system", "content", "instructions",
                               "query", "question", "text"),
             etiqueta="llamada a un modelo de lenguaje"),
    Sumidero("llm_prompt", colas=("chat.completions.create", "responses.create", "messages.create",
                                  "completions.create", "generate_content", "generate_text", "chat.send_message"),
             args=("*",), kws=("messages", "prompt", "input", "contents", "system", "content", "instructions",
                               "query", "question", "text"), confianza="media",
             etiqueta="llamada a un modelo de lenguaje"),
    Sumidero("llm_prompt", colas=("invoke", "predict", "ainvoke", "generate"), args=("*",),
             kws=("input", "prompt", "messages"),
             recv_re=r"(llm|chat|model|gpt|claude|agent|chain|gemini|mistral|assistant)", confianza="media",
             etiqueta="llamada a un modelo de lenguaje"),
]


# --------------------------------------------------------------------------
# Saneadores y funciones conocidas
# --------------------------------------------------------------------------

TODO = frozenset(CLASES_INYECCION)

# nombre cualificado -> clases que neutraliza
SANEADORES: dict[str, frozenset] = {}


def _san(nombres, clases):
    for n in nombres:
        SANEADORES[n] = frozenset(clases)


_san(("shlex.quote", "pipes.quote", "shlex.join"), {"cmd", "cmd_arg"})
_san(("html.escape", "markupsafe.escape", "flask.escape", "jinja2.escape", "django.utils.html.escape",
      "django.utils.html.conditional_escape", "bleach.clean", "cgi.escape", "xml.sax.saxutils.escape",
      "django.utils.html.format_html", "urllib.parse.quote", "urllib.parse.quote_plus", "quote", "quote_plus"),
     {"xss"})
_san(("repr", "ascii", "json.dumps"), {"log"})
_san(("os.path.basename", "werkzeug.utils.secure_filename", "secure_filename", "pathvalidate.sanitize_filename"),
     {"path"})
_san(("re.escape",), {"regex"})
_san(("psycopg2.sql.Identifier", "psycopg2.sql.Literal"), {"sql"})
_san(("ast.literal_eval",), {"code"})
_san(("uuid.UUID", "ipaddress.ip_address", "ipaddress.ip_network", "ipaddress.IPv4Address",
      "ipaddress.IPv6Address", "decimal.Decimal", "fractions.Fraction"), TODO)

# Funciones que devuelven un valor sin datos del atacante aprovechables.
LIMPIAN_TODO = frozenset({"len", "int", "float", "bool", "ord", "hash", "id", "isinstance", "issubclass",
                          "type", "callable", "range", "round", "abs", "sum", "divmod", "print", "hex", "oct",
                          "bin", "complex", "ascii_letters", "math.floor", "math.ceil", "math.sqrt",
                          "time.time", "time.sleep", "random.random", "random.randint", "random.choice",
                          "uuid.uuid4", "uuid.uuid1", "secrets.token_hex", "secrets.token_urlsafe",
                          "secrets.token_bytes", "datetime.datetime.now", "datetime.date.today"})
METODOS_LIMPIOS = frozenset({"isdigit", "isalpha", "isalnum", "isnumeric", "isidentifier", "isdecimal",
                             "isspace", "isupper", "islower", "startswith", "endswith", "count", "find",
                             "index", "rfind", "rindex", "hexdigest", "digest", "__len__", "is_dir",
                             "is_file", "exists", "is_absolute", "is_relative_to"})

# Métodos que, además de devolver el dato, guardan el argumento en el objeto receptor.
METODOS_MUTADORES = frozenset({"append", "extend", "add", "update", "insert", "setdefault", "write",
                               "writelines", "put", "appendleft", "push", "extendleft", "put_nowait",
                               "__setitem__", "send", "sendall"})

# Conocidos: transforman o transportan texto; el dato sigue contaminado sin dudas.
PROPAGA_CONOCIDOS = frozenset({
    "format", "format_map", "join", "strip", "lstrip", "rstrip", "lower", "upper", "title", "capitalize",
    "replace", "split", "rsplit", "splitlines", "encode", "decode", "zfill", "ljust", "rjust", "center",
    "expandtabs", "partition", "rpartition", "translate", "casefold", "swapcase", "removeprefix",
    "removesuffix", "get", "pop", "popitem", "copy", "items", "keys", "values", "read", "readline",
    "readlines", "getvalue", "json", "text", "content", "loads", "dumps", "b64decode", "b64encode",
    "unquote", "unquote_plus", "urlencode", "str", "bytes", "bytearray", "list", "tuple", "set", "dict",
    "sorted", "reversed", "enumerate", "zip", "map", "filter", "iter", "next", "min", "max", "repr",
    "frozenset", "memoryview", "fspath", "normpath", "abspath", "realpath", "join", "dirname", "expanduser",
    "resolve", "with_name", "with_suffix", "joinpath", "parent", "as_posix", "Path", "PurePath", "open",
    "safe_load", "load", "loads", "safe_load_all", "reader", "DictReader", "findall", "group", "groups",
    "sub", "match", "search", "fullmatch", "lstrip", "decompress", "compress", "dedent", "indent",
    "wrap", "fill", "quote", "unescape", "urlparse", "urlsplit", "parse_qs", "parse_qsl", "getlist",
    "getall", "getfirst", "to_dict", "model_dump", "dict", "asdict", "astuple", "deepcopy", "pformat",
    "StringIO", "BytesIO", "Template", "substitute", "safe_substitute", "chain", "islice", "groupby",
    "get_json", "get_data", "get_text", "readall", "iter_content", "iter_lines", "iterdir", "glob", "rglob",
})

METODOS_COMUNES = frozenset({
    "get", "set", "add", "run", "read", "write", "close", "open", "send", "start", "stop", "update",
    "delete", "remove", "append", "items", "keys", "values", "join", "format", "load", "dump", "loads",
    "dumps", "main", "init", "setup", "clear", "copy", "pop", "push", "find", "count", "index", "sort",
    "execute", "fetch", "query", "call", "next", "exit", "wait", "kill", "flush", "seek", "tell",
})


# --------------------------------------------------------------------------
# Catálogo ejecutable
# --------------------------------------------------------------------------

class Catalogo:
    def __init__(self, fuentes_archivo: bool = False):
        self.fuentes_archivo = fuentes_archivo
        self.fuentes_obj: dict[str, Fuente] = {}
        self.fuentes_llam: dict[str, list[Fuente]] = {}
        self.fuentes_cola: dict[str, list[Fuente]] = {}
        self.sum_nombre: dict[str, list[Sumidero]] = {}
        self.sum_cola: dict[str, list[Sumidero]] = {}
        self.saneadores: dict[str, frozenset] = dict(SANEADORES)
        for f in FUENTES:
            self.anadir_fuente(f)
        for s in SUMIDEROS:
            self.anadir_sumidero(s)

    def anadir_fuente(self, f: Fuente) -> None:
        if f.opcional == "archivo" and not self.fuentes_archivo:
            return
        for n in f.nombres:
            if f.modo == "objeto":
                self.fuentes_obj[n] = f
            else:
                self.fuentes_llam.setdefault(n, []).append(f)
        for c in f.colas:
            self.fuentes_cola.setdefault(c, []).append(f)

    def anadir_sumidero(self, s: Sumidero) -> None:
        for n in s.nombres:
            self.sum_nombre.setdefault(n, []).append(s)
        for c in s.colas:
            self.sum_cola.setdefault(c, []).append(s)

    def anadir_saneador(self, nombre: str, clases) -> None:
        self.saneadores[nombre] = frozenset(TODO if clases == "todo" else clases)

    # --- búsquedas ---
    def fuente_objeto(self, qn: str | None) -> Fuente | None:
        return self.fuentes_obj.get(qn) if qn else None

    def fuentes_de_llamada(self, qn, attrs, raiz) -> list[Fuente]:
        r = list(self.fuentes_llam.get(qn, ())) if qn else []
        for cola in _colas(attrs):
            for f in self.fuentes_cola.get(cola, ()):
                if f.recv_re and not (raiz and re.search(f.recv_re, raiz, re.I)):
                    continue
                r.append(f)
        return r

    def sumideros_de(self, qn, attrs, raiz, usar_colas: bool = True) -> list[Sumidero]:
        r = list(self.sum_nombre.get(qn, ())) if qn else []
        if usar_colas:
            for cola in _colas(attrs):
                for s in self.sum_cola.get(cola, ()):
                    if s.recv_re and not (raiz and re.search(s.recv_re, raiz, re.I)):
                        continue
                    if s not in r:
                        r.append(s)
        return r

    def saneador(self, qn) -> frozenset | None:
        return self.saneadores.get(qn) if qn else None


def _colas(attrs):
    n = len(attrs)
    for k in range(1, min(3, n) + 1):
        yield ".".join(attrs[-k:])
