"""Estructuras de datos del analizador.

Un dato no confiable se representa con un `Taint`: de dónde viene, por qué
pasos ha viajado y qué clases de vulnerabilidad ya han sido neutralizadas por
un saneador. Un conjunto de taints es un `Taints`. Todo es inmutable.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

SEVERIDADES = ("info", "baja", "media", "alta", "critica")
ORDEN_SEV = {s: i for i, s in enumerate(SEVERIDADES)}

CLASES_INYECCION = frozenset({
    "cmd", "cmd_arg", "code", "sql", "path", "ssrf", "deser", "xss", "ssti",
    "redirect", "xxe", "regex", "log", "llm_prompt",
})

# Orígenes que un atacante remoto controla y orígenes locales (el que ejecuta
# el programa). La diferencia baja la gravedad de los hallazgos.
ORIGENES_LOCALES = frozenset({"argv", "stdin", "entorno", "archivo"})
MAX_PASOS = 16


@dataclass(frozen=True)
class Paso:
    ruta: str
    linea: int
    col: int
    codigo: str
    texto: str

    def ubicacion(self) -> str:
        return f"{self.ruta}:{self.linea}"


@dataclass(frozen=True)
class Taint:
    tipo: str                       # http, red, llm, argv, stdin, entorno, archivo, param:N
    origen: Paso
    pasos: tuple = ()
    limpio: frozenset = frozenset()  # clases de vulnerabilidad ya neutralizadas
    incierto: bool = False          # pasó por una función externa desconocida

    @property
    def clave(self) -> tuple:
        o = self.origen
        return (self.tipo, o.ruta, o.linea, o.col, self.limpio, self.incierto)

    @property
    def simbolico(self) -> bool:
        return self.tipo.startswith("param:")

    def con_paso(self, paso: Paso) -> "Taint":
        if self.pasos and self.pasos[-1].linea == paso.linea and self.pasos[-1].texto == paso.texto \
                and self.pasos[-1].ruta == paso.ruta:
            return self
        pasos = self.pasos + (paso,)
        if len(pasos) > MAX_PASOS:
            pasos = pasos[:5] + pasos[-(MAX_PASOS - 5):]
        return replace(self, pasos=pasos)

    def limpiar(self, clases) -> "Taint":
        nuevas = self.limpio | frozenset(clases)
        return self if nuevas == self.limpio else replace(self, limpio=nuevas)

    def marcar_incierto(self) -> "Taint":
        return self if self.incierto else replace(self, incierto=True)


class Taints:
    """Conjunto de taints indexado por clave; conserva el recorrido más corto."""
    __slots__ = ("d",)

    def __init__(self, items=()):
        self.d: dict = {}
        for t in items:
            self._poner(t)

    def _poner(self, t: Taint) -> None:
        actual = self.d.get(t.clave)
        if actual is None or len(t.pasos) < len(actual.pasos):
            self.d[t.clave] = t

    def __bool__(self) -> bool:
        return bool(self.d)

    def __iter__(self):
        return iter(self.d.values())

    def __len__(self) -> int:
        return len(self.d)

    def claves(self) -> frozenset:
        return frozenset(self.d)

    def union(self, otro: "Taints") -> "Taints":
        if not otro.d:
            return self
        if not self.d:
            return otro
        r = Taints()
        r.d = dict(self.d)
        for t in otro.d.values():
            r._poner(t)
        return r

    def mapear(self, f) -> "Taints":
        return Taints(f(t) for t in self.d.values())

    def con_paso(self, paso: Paso) -> "Taints":
        return self.mapear(lambda t: t.con_paso(paso)) if self.d else self

    def limpiar(self, clases) -> "Taints":
        return self.mapear(lambda t: t.limpiar(clases)) if self.d else self

    def marcar_incierto(self) -> "Taints":
        return self.mapear(lambda t: t.marcar_incierto()) if self.d else self


VACIO = Taints()


@dataclass
class Hallazgo:
    regla: str
    clase: str
    titulo: str
    cwe: str
    severidad: str
    confianza: str
    ruta: str
    linea: int
    col: int
    codigo: str
    mensaje: str
    remedio: str
    origen_tipo: str = ""
    traza: list = None              # lista de Paso, del origen al sumidero
    huella: str = ""
    owasp: str = ""

    def a_dict(self) -> dict:
        return {
            "regla": self.regla, "clase": self.clase, "titulo": self.titulo, "cwe": self.cwe,
            "owasp": self.owasp, "severidad": self.severidad, "confianza": self.confianza,
            "ruta": self.ruta, "linea": self.linea, "columna": self.col, "codigo": self.codigo,
            "mensaje": self.mensaje, "remedio": self.remedio, "origen": self.origen_tipo,
            "traza": [{"ruta": p.ruta, "linea": p.linea, "columna": p.col, "codigo": p.codigo,
                       "texto": p.texto} for p in (self.traza or [])],
            "huella": self.huella,
        }


def bajar(sev: str, niveles: int = 1) -> str:
    return SEVERIDADES[max(0, ORDEN_SEV[sev] - niveles)]
