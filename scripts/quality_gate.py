#!/usr/bin/env python3
"""Quality gate del laboratorio 3.

Lee los reportes que generan los escaneres (Semgrep, CodeQL, SpotBugs,
Trivy sobre el SBOM y OWASP Dependency-Check) y decide si el pipeline
bloquea o aprueba. Los escaneres solo fallan por errores tecnicos; el
que decide por hallazgos es este script, y es fail-closed: si falta un
reporte obligatorio o no se puede interpretar, bloquea.

Solo usa la biblioteca estandar de Python.
"""

import argparse
import datetime
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

EXIT_OK = 0
EXIT_BLOQUEADO = 1
EXIT_FAIL_CLOSED = 2

UMBRAL_CVSS = 7.0
UMBRAL_CODEQL_SECURITY_SEVERITY = 7.0
SPOTBUGS_PRIORIDAD_MAXIMA = 2  # 1 y 2 bloquean; 3 (SPRING_ENDPOINT, etc.) es informativo
MAX_HALLAZGOS_MOSTRADOS = 20


class ReporteCorrupto(Exception):
    """Un reporte existe pero no se pudo interpretar (JSON/XML invalido o con forma inesperada)."""


def escapar_markdown(texto):
    """Neutraliza caracteres que romperian una tabla Markdown (``|``, ``<``, ``>``, saltos de linea)."""
    if texto is None:
        return ""
    texto = str(texto)
    texto = texto.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    texto = texto.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")
    return texto


def escapar_anotacion(texto):
    """Neutraliza ``%``, ``\\r`` y ``\\n`` para que no rompan un comando ``::error::`` de Actions."""
    if texto is None:
        return ""
    texto = str(texto)
    return texto.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _cargar_json(ruta):
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise ReporteCorrupto(f"{ruta}: {exc}") from exc


def _cargar_xml(ruta):
    try:
        return ET.parse(ruta).getroot()
    except (OSError, ET.ParseError) as exc:
        raise ReporteCorrupto(f"{ruta}: {exc}") from exc


def _mensaje_sarif(resultado):
    mensaje = (resultado.get("message") or {}).get("text", "")
    ubicaciones = resultado.get("locations") or []
    if ubicaciones:
        loc = (ubicaciones[0] or {}).get("physicalLocation", {}) or {}
        archivo = (loc.get("artifactLocation") or {}).get("uri", "")
        linea = (loc.get("region") or {}).get("startLine", "")
        if archivo:
            return f"{archivo}:{linea} - {mensaje}"
    return mensaje


def _reglas_sarif(run):
    """Combina ``tool.driver.rules`` y ``tool.extensions[].rules``, indexadas por id y por posicion."""
    por_id, por_indice = {}, {}

    def agregar(reglas):
        for i, regla in enumerate(reglas):
            if regla.get("id") is not None:
                por_id[regla["id"]] = regla
            por_indice[i] = regla

    tool = run.get("tool", {}) or {}
    agregar((tool.get("driver") or {}).get("rules", []) or [])
    for extension in tool.get("extensions", []) or []:
        agregar(extension.get("rules", []) or [])
    return por_id, por_indice


def _regla_de(por_id, por_indice, resultado):
    return por_id.get(resultado.get("ruleId")) or por_indice.get(resultado.get("ruleIndex")) or {}


# ---------------------------------------------------------------------------
# Semgrep (SARIF): bloquea si el nivel resuelto del resultado es "error".
# El SARIF de Semgrep no trae "level" en cada resultado: esta en
# runs[].tool.driver.rules[].defaultConfiguration.level, por ruleId/ruleIndex.
# ---------------------------------------------------------------------------

def evaluar_semgrep(ruta_sarif):
    datos = _cargar_json(ruta_sarif)
    hallazgos = []
    for run in datos.get("runs", []) or []:
        por_id, por_indice = _reglas_sarif(run)
        for resultado in run.get("results", []) or []:
            regla = _regla_de(por_id, por_indice, resultado)
            nivel = resultado.get("level") or (regla.get("defaultConfiguration") or {}).get("level") or "warning"
            if nivel == "error":
                hallazgos.append({
                    "herramienta": "Semgrep",
                    "id": resultado.get("ruleId") or "(sin id)",
                    "detalle": _mensaje_sarif(resultado),
                })
    return hallazgos


# ---------------------------------------------------------------------------
# CodeQL (SARIF): bloquea si la regla trae properties["security-severity"] >= 7.0.
# Las reglas pueden estar en tool.driver.rules o en tool.extensions[].rules.
# ---------------------------------------------------------------------------

def evaluar_codeql(ruta_sarif):
    datos = _cargar_json(ruta_sarif)
    hallazgos = []
    for run in datos.get("runs", []) or []:
        por_id, por_indice = _reglas_sarif(run)
        for resultado in run.get("results", []) or []:
            regla = _regla_de(por_id, por_indice, resultado)
            severidad = (regla.get("properties") or {}).get("security-severity")
            try:
                severidad = float(severidad)
            except (TypeError, ValueError):
                continue
            if severidad >= UMBRAL_CODEQL_SECURITY_SEVERITY:
                hallazgos.append({
                    "herramienta": "CodeQL",
                    "id": resultado.get("ruleId") or "(sin id)",
                    "detalle": f"security-severity={severidad} - {_mensaje_sarif(resultado)}",
                })
    return hallazgos


# ---------------------------------------------------------------------------
# OWASP Dependency-Check (JSON): bloquea si una vulnerabilidad NO suprimida
# tiene CVSS >= 7 (v2, v3 o v4) o severity HIGH/CRITICAL. Las suprimidas
# viven en "suppressedVulnerabilities" y no se leen aqui.
# ---------------------------------------------------------------------------

def evaluar_dependency_check(ruta_json):
    datos = _cargar_json(ruta_json)
    hallazgos = []
    for dependencia in datos.get("dependencies", []) or []:
        for vuln in dependencia.get("vulnerabilities", []) or []:
            cvss_maximo = None
            for clave in ("cvssv3", "cvssv4", "cvssv2"):
                valor = (vuln.get(clave) or {}).get("baseScore")
                if valor is not None:
                    try:
                        valor = float(valor)
                    except (TypeError, ValueError):
                        continue
                    cvss_maximo = valor if cvss_maximo is None else max(cvss_maximo, valor)
            severidad = (vuln.get("severity") or "").upper()
            if (cvss_maximo is not None and cvss_maximo >= UMBRAL_CVSS) or severidad in ("HIGH", "CRITICAL"):
                hallazgos.append({
                    "herramienta": "Dependency-Check",
                    "id": vuln.get("name") or "(sin id)",
                    "detalle": (
                        f"{dependencia.get('fileName', '?')} - severidad="
                        f"{severidad or 'N/D'} cvss={cvss_maximo if cvss_maximo is not None else 'N/D'}"
                    ),
                })
    return hallazgos


# ---------------------------------------------------------------------------
# SpotBugs + FindSecBugs (XML): bloquea BugInstance con category="SECURITY"
# y priority <= 2 (1 y 2 bloquean; 3, como SPRING_ENDPOINT, es informativo).
# ---------------------------------------------------------------------------

def evaluar_spotbugs(ruta_xml):
    raiz = _cargar_xml(ruta_xml)
    hallazgos = []
    for bug in raiz.findall("BugInstance"):
        categoria = bug.get("category")
        try:
            prioridad = int(bug.get("priority", "999"))
        except ValueError:
            prioridad = 999
        if categoria == "SECURITY" and prioridad <= SPOTBUGS_PRIORIDAD_MAXIMA:
            mensaje = bug.findtext("ShortMessage", default="") or ""
            clase = bug.find("Class")
            ubicacion = clase.get("classname") if clase is not None else "?"
            hallazgos.append({
                "herramienta": "SpotBugs",
                "id": bug.get("type") or "(sin tipo)",
                "detalle": f"{ubicacion} (prioridad {prioridad}) - {mensaje}",
            })
    return hallazgos


# ---------------------------------------------------------------------------
# Trivy (JSON, SBOM de la app o imagen): bloquea HIGH o CRITICAL.
# No se usa --ignore-unfixed sobre las librerias de la aplicacion.
#
# Trivy no conoce dependency-check-suppressions.xml (ese archivo solo lo lee
# el plugin de Dependency-Check). Para no bloquear dos veces por el mismo
# hallazgo ya documentado y aceptado alli, este evaluador vuelve a leer el
# mismo XML y descarta los hallazgos de Trivy que coincidan exactamente en
# CVE + packageUrl (version exacta) con una supresion vigente.
# ---------------------------------------------------------------------------

NS_SUPRESIONES = {"dc": "https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd"}


def cargar_supresiones(ruta):
    """Lee las entradas vigentes de dependency-check-suppressions.xml.

    Honra tanto packageUrl exacto como con ``regex="true"`` (Dependency-Check
    soporta ambos; un regex sigue exigiendo anclar la version exacta, por
    ejemplo ``^pkg:maven/org\\.springframework/[^@]+@6\\.2\\.19$``, para que
    siga sin aplicar en cuanto la dependencia cambie de version). Si tienen
    `until`, debe no haber vencido -- una supresion vencida deja de aplicar,
    igual que en Dependency-Check, para forzar la re-revision en vez de
    ocultar el hallazgo para siempre.
    """
    ruta = Path(ruta)
    if not ruta.is_file():
        return []
    try:
        raiz = _cargar_xml(ruta)
    except ReporteCorrupto:
        return []

    hoy = datetime.date.today()
    supresiones = []
    for nodo in raiz.findall("dc:suppress", NS_SUPRESIONES):
        until = nodo.get("until")
        if until:
            try:
                if hoy > datetime.date.fromisoformat(until.rstrip("Zz")):
                    continue  # vencida: no se aplica
            except ValueError:
                continue
        pkg_nodo = nodo.find("dc:packageUrl", NS_SUPRESIONES)
        cve_nodos = nodo.findall("dc:cve", NS_SUPRESIONES)
        if pkg_nodo is None or not cve_nodos:
            continue
        es_regex = (pkg_nodo.get("regex") or "").lower() == "true"
        patron = (pkg_nodo.text or "").strip()
        if es_regex:
            try:
                patron_compilado = re.compile(patron)
            except re.error:
                continue
        else:
            patron_compilado = None
        # Un <suppress> puede listar varios <cve> para el mismo packageUrl.
        for cve_nodo in cve_nodos:
            if (cve_nodo.text or "").strip():
                supresiones.append({
                    "cve": cve_nodo.text.strip(),
                    "package_url": patron,
                    "regex": patron_compilado,
                })
    return supresiones


def _trivy_package_url(pkg_name, version):
    grupo_artefacto = (pkg_name or "").split(":", 1)
    if len(grupo_artefacto) == 2:
        return f"pkg:maven/{grupo_artefacto[0]}/{grupo_artefacto[1]}@{version}"
    return f"pkg:maven/{pkg_name}@{version}"


def _coincide_supresion(supresion, vuln_id, pkg_url):
    if supresion["cve"] != vuln_id:
        return False
    if supresion["regex"] is not None:
        return supresion["regex"].match(pkg_url) is not None
    return supresion["package_url"] == pkg_url


def evaluar_trivy(ruta_json, supresiones=None):
    datos = _cargar_json(ruta_json)
    supresiones = supresiones or []
    hallazgos = []
    for resultado in datos.get("Results", []) or []:
        for vuln in resultado.get("Vulnerabilities", []) or []:
            severidad = (vuln.get("Severity") or "").upper()
            if severidad not in ("HIGH", "CRITICAL"):
                continue
            vuln_id = vuln.get("VulnerabilityID") or "(sin id)"
            pkg_url = _trivy_package_url(vuln.get("PkgName"), vuln.get("InstalledVersion"))
            if any(_coincide_supresion(s, vuln_id, pkg_url) for s in supresiones):
                continue
            hallazgos.append({
                "herramienta": "Trivy",
                "id": vuln_id,
                "detalle": f"{vuln.get('PkgName', '?')}@{vuln.get('InstalledVersion', '?')} - {severidad}",
            })
    return hallazgos


# ---------------------------------------------------------------------------
# Orquestacion: que reporte corresponde a cada herramienta, donde buscarlo
# (carpeta de artifact de Actions, o nombre plano para evidencias locales)
# y con que funcion evaluarlo.
# ---------------------------------------------------------------------------

REPORTES = {
    "semgrep": {
        "etiqueta": "Semgrep",
        "artifact": "report-semgrep",
        "nombres": ["semgrep-results.sarif", "semgrep.sarif"],
        "evaluar": evaluar_semgrep,
    },
    "codeql": {
        "etiqueta": "CodeQL",
        "artifact": "report-codeql",
        "nombres": ["*.sarif"],
        "evaluar": evaluar_codeql,
        # CodeQL no corre en local (ver quality-gate.md): su "*.sarif" solo
        # se busca dentro de la carpeta propia del artifact, nunca en forma
        # plana, para no confundirlo con el .sarif de otra herramienta
        # (p.ej. dependency-check-report.sarif) en evidencias/locales/.
        "solo_artifact": True,
    },
    "spotbugs": {
        "etiqueta": "SpotBugs",
        "artifact": "report-spotbugs",
        "nombres": ["spotbugsXml.xml"],
        "evaluar": evaluar_spotbugs,
    },
    "sbom-trivy": {
        "etiqueta": "Trivy (SBOM)",
        "artifact": "report-sbom-trivy",
        "nombres": ["sca-report.json"],
        "evaluar": evaluar_trivy,
    },
    "dependency-check": {
        "etiqueta": "Dependency-Check",
        "artifact": "report-dependency-check",
        "nombres": ["dependency-check-report.json"],
        "evaluar": evaluar_dependency_check,
    },
}

ORDEN_REPORTES = ("semgrep", "codeql", "spotbugs", "sbom-trivy", "dependency-check")


def _buscar_archivos(reportes_dir, spec):
    """Busca el reporte en la carpeta de artifact de Actions y, si no esta, en forma plana.

    Esto permite correr el mismo script contra los artifacts descargados en
    Actions (``reportes/report-semgrep/semgrep-results.sarif``) o contra una
    carpeta de evidencias locales con los archivos sueltos
    (``evidencias/locales/antes/semgrep.sarif``).
    """
    base = Path(reportes_dir)
    carpetas = (base / spec["artifact"],) if spec.get("solo_artifact") else (base / spec["artifact"], base)
    for nombre in spec["nombres"]:
        for carpeta in carpetas:
            encontrados = sorted(carpeta.glob(nombre))
            if encontrados:
                return encontrados
    return []


def evaluar_pipeline(reportes_dir, needs, requeridos, ruta_supresiones="dependency-check-suppressions.xml"):
    """Evalua todos los reportes disponibles y los resultados de los jobs previos.

    ``needs`` es el contexto ``needs`` de Actions (o un dict equivalente en
    pruebas/local), y ``requeridos`` es el conjunto de claves de ``REPORTES``
    que deben existir y poder leerse (fail-closed si no).
    """
    fallos_previos = sorted(
        nombre for nombre, info in (needs or {}).items()
        if (info or {}).get("result") in ("failure", "cancelled")
    )

    supresiones = cargar_supresiones(ruta_supresiones)
    hallazgos = []
    reportes_faltantes = []
    por_herramienta = {}

    for clave in ORDEN_REPORTES:
        spec = REPORTES[clave]
        archivos = _buscar_archivos(reportes_dir, spec)
        if not archivos:
            if clave in requeridos:
                reportes_faltantes.append(spec["etiqueta"])
            por_herramienta[clave] = None
            continue
        try:
            encontrados = []
            for archivo in archivos:
                if clave == "sbom-trivy":
                    encontrados.extend(spec["evaluar"](archivo, supresiones))
                else:
                    encontrados.extend(spec["evaluar"](archivo))
        except ReporteCorrupto:
            # Un reporte corrupto siempre bloquea fail-closed, aunque la
            # herramienta no fuera obligatoria para este evento: si el
            # archivo existe pero no se puede leer, algo fallo de verdad.
            reportes_faltantes.append(spec["etiqueta"])
            por_herramienta[clave] = None
            continue
        por_herramienta[clave] = encontrados
        hallazgos.extend(encontrados)

    return {
        "fallos_previos": fallos_previos,
        "reportes_faltantes": sorted(reportes_faltantes),
        "hallazgos": hallazgos,
        "por_herramienta": por_herramienta,
    }


def decidir_salida(resultado):
    if resultado["fallos_previos"]:
        return EXIT_BLOQUEADO
    if resultado["reportes_faltantes"]:
        return EXIT_FAIL_CLOSED
    if resultado["hallazgos"]:
        return EXIT_BLOQUEADO
    return EXIT_OK


def generar_resumen_markdown(resultado, requeridos):
    lineas = ["# Quality Gate", ""]

    if resultado["fallos_previos"]:
        detalle = ", ".join(escapar_markdown(j) for j in resultado["fallos_previos"])
        lineas.append(f"**Resultado: BLOQUEADO** — job(s) previo(s) en failure/cancelled: {detalle}")
    elif resultado["reportes_faltantes"]:
        detalle = ", ".join(escapar_markdown(r) for r in resultado["reportes_faltantes"])
        lineas.append(f"**Resultado: BLOQUEADO (fail-closed)** — faltan reportes obligatorios o no se pudieron leer: {detalle}")
    elif resultado["hallazgos"]:
        lineas.append(f"**Resultado: BLOQUEADO** — {len(resultado['hallazgos'])} hallazgo(s) critico(s)")
    else:
        lineas.append("**Resultado: APROBADO**")

    lineas.append("")
    lineas.append("| Herramienta | Bloqueantes | Estado |")
    lineas.append("|---|---|---|")
    for clave in ORDEN_REPORTES:
        etiqueta = REPORTES[clave]["etiqueta"]
        encontrados = resultado["por_herramienta"].get(clave)
        if encontrados is None:
            estado = "obligatorio, falta o no se pudo leer" if clave in requeridos else "no evaluado en esta ejecucion"
            lineas.append(f"| {escapar_markdown(etiqueta)} | - | {estado} |")
        else:
            lineas.append(f"| {escapar_markdown(etiqueta)} | {len(encontrados)} | evaluado |")

    if resultado["hallazgos"]:
        lineas.append("")
        lineas.append("## Principales hallazgos bloqueantes")
        lineas.append("")
        lineas.append("| Herramienta | Id | Detalle |")
        lineas.append("|---|---|---|")
        mostrados = resultado["hallazgos"][:MAX_HALLAZGOS_MOSTRADOS]
        for h in mostrados:
            lineas.append(
                f"| {escapar_markdown(h['herramienta'])} | {escapar_markdown(h['id'])} | {escapar_markdown(h['detalle'])} |"
            )
        restantes = len(resultado["hallazgos"]) - len(mostrados)
        if restantes > 0:
            lineas.append(f"| ... | ... | (+{restantes} hallazgo(s) mas, ver el reporte completo) |")

    return "\n".join(lineas) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Quality gate que lee los reportes de los escaneos de seguridad.")
    parser.add_argument(
        "--reportes-dir", default="reportes",
        help="Carpeta con los reportes descargados (artifacts de Actions o evidencias locales).",
    )
    parser.add_argument(
        "--requeridos",
        default="semgrep,codeql,spotbugs,sbom-trivy,dependency-check",
        help="Claves de reportes obligatorias, separadas por coma (fail-closed si faltan).",
    )
    parser.add_argument(
        "--needs-json", default=None,
        help="Ruta a un archivo JSON con el contexto 'needs'. Por defecto se lee de la variable NEEDS_JSON.",
    )
    parser.add_argument(
        "--resumen", default=None,
        help="Archivo donde escribir el Step Summary. Por defecto, $GITHUB_STEP_SUMMARY o la salida estandar.",
    )
    parser.add_argument(
        "--supresiones", default="dependency-check-suppressions.xml",
        help=(
            "Archivo de supresiones de Dependency-Check. Tambien se aplica a "
            "los hallazgos de Trivy (que no conoce ese archivo), para no "
            "bloquear dos veces por el mismo CVE ya documentado como no "
            "aplicable. Si no existe, no se suprime nada."
        ),
    )
    args = parser.parse_args(argv)

    requeridos = {c.strip() for c in args.requeridos.split(",") if c.strip()}

    if args.needs_json:
        with open(args.needs_json, "r", encoding="utf-8") as f:
            needs = json.load(f)
    else:
        needs_env = os.environ.get("NEEDS_JSON", "").strip()
        needs = json.loads(needs_env) if needs_env else {}

    resultado = evaluar_pipeline(args.reportes_dir, needs, requeridos, args.supresiones)
    resumen = generar_resumen_markdown(resultado, requeridos)

    destino = args.resumen or os.environ.get("GITHUB_STEP_SUMMARY")
    if destino:
        with open(destino, "a", encoding="utf-8") as f:
            f.write(resumen)
    else:
        print(resumen)

    if resultado["fallos_previos"]:
        for job in resultado["fallos_previos"]:
            print(f"::error::El job '{escapar_anotacion(job)}' termino en failure o cancelled")
    if resultado["reportes_faltantes"]:
        for reporte in resultado["reportes_faltantes"]:
            print(f"::error::Falta el reporte obligatorio de {escapar_anotacion(reporte)}, o no se pudo leer")
    if resultado["hallazgos"]:
        for h in resultado["hallazgos"][:MAX_HALLAZGOS_MOSTRADOS]:
            print(f"::error::[{escapar_anotacion(h['herramienta'])}] {escapar_anotacion(h['id'])}: {escapar_anotacion(h['detalle'])}")

    salida = decidir_salida(resultado)
    if salida == EXIT_OK:
        print("Quality gate: APROBADO")
    return salida


if __name__ == "__main__":
    sys.exit(main())
