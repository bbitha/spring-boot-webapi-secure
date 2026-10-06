#!/usr/bin/env python3
"""Pruebas unitarias del quality gate (ver referencias/quality-gate.md).

Casos minimos exigidos: un hallazgo critico por herramienta que bloquea,
todo limpio que aprueba, reporte faltante, JSON corrupto, job previo en
failure, resultados suprimidos que no cuentan, SARIF de Semgrep sin
"level" por resultado, CodeQL con la regla en "extensions", y texto con
caracteres de inyeccion que debe salir escapado.

Se ejecuta con: python3 -m unittest scripts/test_quality_gate.py -v
"""

import json
import tempfile
import unittest
from pathlib import Path

import quality_gate as gate


def _escribir_json(ruta, datos):
    ruta.parent.mkdir(parents=True, exist_ok=True)
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(datos, f)


def _escribir_texto(ruta, texto):
    ruta.parent.mkdir(parents=True, exist_ok=True)
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(texto)


def _sarif_semgrep(nivel_regla, con_level_en_resultado=False):
    """SARIF minimo con una sola regla y un solo resultado, al estilo Semgrep real:
    el resultado normalmente NO trae "level"; el nivel vive en la regla."""
    resultado = {
        "ruleId": "lab-java-sql-concatenation",
        "message": {"text": "Entrada HTTP concatenada en una consulta SQL."},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": "src/main/java/Demo.java"},
                "region": {"startLine": 24},
            }
        }],
    }
    if con_level_en_resultado:
        resultado["level"] = nivel_regla
    return {
        "runs": [{
            "tool": {"driver": {"rules": [{
                "id": "lab-java-sql-concatenation",
                "defaultConfiguration": {"level": nivel_regla},
            }]}},
            "results": [resultado],
        }]
    }


def _sarif_codeql(security_severity, regla_en_extensions=False):
    regla = {
        "id": "java/sql-injection",
        "properties": {"security-severity": str(security_severity)},
    }
    driver_rules = [] if regla_en_extensions else [regla]
    extensions = [{"rules": [regla]}] if regla_en_extensions else []
    return {
        "runs": [{
            "tool": {
                "driver": {"rules": driver_rules},
                "extensions": extensions,
            },
            "results": [{
                "ruleId": "java/sql-injection",
                "message": {"text": "Posible inyeccion SQL."},
                "locations": [],
            }],
        }]
    }


def _dependency_check(vulnerabilidades=None, suprimidas=None):
    return {
        "dependencies": [{
            "fileName": "commons-text-1.9.jar",
            "vulnerabilities": vulnerabilidades or [],
            "suppressedVulnerabilities": suprimidas or [],
        }]
    }


def _spotbugs_xml(category, priority, tipo="SQL_INJECTION_SPRING_JDBC"):
    return (
        "<BugCollection>"
        f"<BugInstance category='{category}' priority='{priority}' type='{tipo}'>"
        "<ShortMessage>Hallazgo de prueba</ShortMessage>"
        "<Class classname='bo.edu.devsecops.Demo'/>"
        "</BugInstance>"
        "</BugCollection>"
    )


def _trivy(severidad):
    return {
        "Results": [{
            "Target": "app",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2022-42889",
                "PkgName": "commons-text",
                "InstalledVersion": "1.9",
                "Severity": severidad,
            }],
        }]
    }


class EvaluarPorHerramientaTests(unittest.TestCase):
    """Un hallazgo critico por cada herramienta debe producir exactamente un bloqueante."""

    def test_semgrep_bloquea_con_nivel_error_en_la_regla(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "semgrep.sarif"
            _escribir_json(ruta, _sarif_semgrep("error"))
            hallazgos = gate.evaluar_semgrep(ruta)
        self.assertEqual(len(hallazgos), 1)
        self.assertEqual(hallazgos[0]["herramienta"], "Semgrep")

    def test_semgrep_no_bloquea_con_nivel_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "semgrep.sarif"
            _escribir_json(ruta, _sarif_semgrep("warning"))
            hallazgos = gate.evaluar_semgrep(ruta)
        self.assertEqual(hallazgos, [])

    def test_codeql_bloquea_con_security_severity_alta(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "codeql.sarif"
            _escribir_json(ruta, _sarif_codeql(8.8))
            hallazgos = gate.evaluar_codeql(ruta)
        self.assertEqual(len(hallazgos), 1)

    def test_codeql_no_bloquea_por_debajo_del_umbral(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "codeql.sarif"
            _escribir_json(ruta, _sarif_codeql(5.4))  # p.ej. stack-trace-exposure
            hallazgos = gate.evaluar_codeql(ruta)
        self.assertEqual(hallazgos, [])

    def test_dependency_check_bloquea_con_cvss_alto(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "dependency-check-report.json"
            vulns = [{"name": "CVE-2022-42889", "severity": "CRITICAL", "cvssv3": {"baseScore": 9.8}}]
            _escribir_json(ruta, _dependency_check(vulnerabilidades=vulns))
            hallazgos = gate.evaluar_dependency_check(ruta)
        self.assertEqual(len(hallazgos), 1)
        self.assertEqual(hallazgos[0]["id"], "CVE-2022-42889")

    def test_spotbugs_bloquea_security_prioridad_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "spotbugsXml.xml"
            _escribir_texto(ruta, _spotbugs_xml("SECURITY", 2))
            hallazgos = gate.evaluar_spotbugs(ruta)
        self.assertEqual(len(hallazgos), 1)

    def test_spotbugs_no_bloquea_prioridad_3(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "spotbugsXml.xml"
            _escribir_texto(ruta, _spotbugs_xml("SECURITY", 3, tipo="SPRING_ENDPOINT"))
            hallazgos = gate.evaluar_spotbugs(ruta)
        self.assertEqual(hallazgos, [])

    def test_spotbugs_no_bloquea_otra_categoria(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "spotbugsXml.xml"
            _escribir_texto(ruta, _spotbugs_xml("MALICIOUS_CODE", 2, tipo="EI_EXPOSE_REP2"))
            hallazgos = gate.evaluar_spotbugs(ruta)
        self.assertEqual(hallazgos, [])

    def test_trivy_bloquea_high_y_critical(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "sca-report.json"
            _escribir_json(ruta, _trivy("CRITICAL"))
            hallazgos = gate.evaluar_trivy(ruta)
        self.assertEqual(len(hallazgos), 1)

    def test_trivy_no_bloquea_medium(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "sca-report.json"
            _escribir_json(ruta, _trivy("MEDIUM"))
            hallazgos = gate.evaluar_trivy(ruta)
        self.assertEqual(hallazgos, [])


class SuprimidosYTramposTests(unittest.TestCase):

    def test_dependency_check_no_cuenta_suprimidas(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "dependency-check-report.json"
            suprimidas = [{"name": "CVE-2022-42889", "severity": "CRITICAL", "cvssv3": {"baseScore": 9.8}}]
            _escribir_json(ruta, _dependency_check(vulnerabilidades=[], suprimidas=suprimidas))
            hallazgos = gate.evaluar_dependency_check(ruta)
        self.assertEqual(hallazgos, [])

    def test_semgrep_sarif_sin_level_por_resultado(self):
        """El resultado no trae "level": el nivel se resuelve por la regla (ruleId)."""
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "semgrep.sarif"
            sarif = _sarif_semgrep("error", con_level_en_resultado=False)
            self.assertNotIn("level", sarif["runs"][0]["results"][0])
            _escribir_json(ruta, sarif)
            hallazgos = gate.evaluar_semgrep(ruta)
        self.assertEqual(len(hallazgos), 1)

    def test_codeql_regla_en_extensions(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "codeql.sarif"
            sarif = _sarif_codeql(8.8, regla_en_extensions=True)
            self.assertEqual(sarif["runs"][0]["tool"]["driver"]["rules"], [])
            _escribir_json(ruta, sarif)
            hallazgos = gate.evaluar_codeql(ruta)
        self.assertEqual(len(hallazgos), 1)

    def test_dependency_check_cvssv4_sin_basescore_no_rompe(self):
        """cvssv4 puede no traer baseScore (como en reportes reales); no debe fallar."""
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "dependency-check-report.json"
            vulns = [{"name": "CVE-X", "severity": "LOW", "cvssv4": {"vectorString": "CVSS:4.0/..."}}]
            _escribir_json(ruta, _dependency_check(vulnerabilidades=vulns))
            hallazgos = gate.evaluar_dependency_check(ruta)
        self.assertEqual(hallazgos, [])


def _poblar_reportes_dir(base, con_dependency_check=True):
    base = Path(base)
    _escribir_json(base / "report-semgrep" / "semgrep-results.sarif", _sarif_semgrep("warning"))
    _escribir_json(base / "report-codeql" / "java-kotlin.sarif", _sarif_codeql(5.0))
    _escribir_texto(base / "report-spotbugs" / "spotbugsXml.xml", _spotbugs_xml("SECURITY", 3, tipo="SPRING_ENDPOINT"))
    _escribir_json(base / "report-sbom-trivy" / "sca-report.json", _trivy("LOW"))
    if con_dependency_check:
        _escribir_json(base / "report-dependency-check" / "dependency-check-report.json", _dependency_check())


class EvaluarPipelineTests(unittest.TestCase):
    """Casos de punta a punta: needs, reportes obligatorios, fail-closed y aprobacion."""

    REQUERIDOS = {"semgrep", "codeql", "spotbugs", "sbom-trivy", "dependency-check"}

    def test_todo_limpio_aprueba(self):
        with tempfile.TemporaryDirectory() as tmp:
            _poblar_reportes_dir(tmp)
            needs = {"build-and-test": {"result": "success"}}
            resultado = gate.evaluar_pipeline(tmp, needs, self.REQUERIDOS)
        self.assertEqual(gate.decidir_salida(resultado), gate.EXIT_OK)
        self.assertEqual(resultado["hallazgos"], [])

    def test_job_previo_en_failure_bloquea(self):
        with tempfile.TemporaryDirectory() as tmp:
            _poblar_reportes_dir(tmp)
            needs = {"build-and-test": {"result": "failure"}}
            resultado = gate.evaluar_pipeline(tmp, needs, self.REQUERIDOS)
        self.assertEqual(gate.decidir_salida(resultado), gate.EXIT_BLOQUEADO)
        self.assertIn("build-and-test", resultado["fallos_previos"])

    def test_job_previo_cancelado_bloquea(self):
        with tempfile.TemporaryDirectory() as tmp:
            _poblar_reportes_dir(tmp)
            needs = {"sast-semgrep": {"result": "cancelled"}}
            resultado = gate.evaluar_pipeline(tmp, needs, self.REQUERIDOS)
        self.assertEqual(gate.decidir_salida(resultado), gate.EXIT_BLOQUEADO)

    def test_job_omitido_a_proposito_no_bloquea(self):
        """sca-dependency-check en 'skipped' (input run_dependency_check=false) no es un fallo."""
        with tempfile.TemporaryDirectory() as tmp:
            _poblar_reportes_dir(tmp, con_dependency_check=False)
            needs = {
                "build-and-test": {"result": "success"},
                "sca-dependency-check": {"result": "skipped"},
            }
            requeridos = {"semgrep", "codeql", "spotbugs", "sbom-trivy"}  # sin dependency-check
            resultado = gate.evaluar_pipeline(tmp, needs, requeridos)
        self.assertEqual(gate.decidir_salida(resultado), gate.EXIT_OK)

    def test_reporte_obligatorio_faltante_es_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            _poblar_reportes_dir(tmp, con_dependency_check=False)
            needs = {"build-and-test": {"result": "success"}}
            resultado = gate.evaluar_pipeline(tmp, needs, self.REQUERIDOS)
        self.assertEqual(gate.decidir_salida(resultado), gate.EXIT_FAIL_CLOSED)
        self.assertIn("Dependency-Check", resultado["reportes_faltantes"])

    def test_reporte_corrupto_es_fail_closed_aunque_no_sea_obligatorio(self):
        with tempfile.TemporaryDirectory() as tmp:
            _poblar_reportes_dir(tmp, con_dependency_check=False)
            _escribir_texto(Path(tmp) / "report-dependency-check" / "dependency-check-report.json", "{ esto no es json")
            needs = {}
            requeridos = {"semgrep", "codeql", "spotbugs", "sbom-trivy"}  # dependency-check NO es obligatorio aqui
            resultado = gate.evaluar_pipeline(tmp, needs, requeridos)
        self.assertEqual(gate.decidir_salida(resultado), gate.EXIT_FAIL_CLOSED)
        self.assertIn("Dependency-Check", resultado["reportes_faltantes"])

    def test_hallazgo_critico_en_un_solo_reporte_bloquea_el_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            _poblar_reportes_dir(tmp)
            _escribir_json(
                Path(tmp) / "report-sbom-trivy" / "sca-report.json",
                _trivy("CRITICAL"),
            )
            needs = {"build-and-test": {"result": "success"}}
            resultado = gate.evaluar_pipeline(tmp, needs, self.REQUERIDOS)
        self.assertEqual(gate.decidir_salida(resultado), gate.EXIT_BLOQUEADO)
        self.assertTrue(any(h["herramienta"] == "Trivy" for h in resultado["hallazgos"]))

    def test_layout_plano_de_evidencias_locales(self):
        """Sin subcarpetas por artifact: los archivos sueltos como en evidencias/locales/antes/."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _escribir_json(base / "semgrep.sarif", _sarif_semgrep("warning"))
            _escribir_texto(base / "spotbugsXml.xml", _spotbugs_xml("SECURITY", 3, tipo="SPRING_ENDPOINT"))
            _escribir_json(base / "sca-report.json", _trivy("LOW"))
            _escribir_json(base / "dependency-check-report.json", _dependency_check())
            needs = {}
            requeridos = {"semgrep", "spotbugs", "sbom-trivy", "dependency-check"}  # sin CodeQL, como en local
            resultado = gate.evaluar_pipeline(tmp, needs, requeridos)
        self.assertEqual(gate.decidir_salida(resultado), gate.EXIT_OK)

    def test_codeql_no_se_confunde_con_otro_sarif_en_layout_plano(self):
        """Regresion: el '*.sarif' de CodeQL no debe recoger dependency-check-report.sarif
        ni semgrep.sarif cuando conviven sueltos en una carpeta de evidencias locales."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _escribir_json(base / "semgrep.sarif", _sarif_semgrep("warning"))
            _escribir_json(base / "dependency-check-report.sarif", _sarif_codeql(9.8))
            needs = {}
            # CodeQL no es obligatorio aqui (no corre en local): debe quedar "no evaluado",
            # no debe aparecer con hallazgos tomados de otro reporte.
            resultado = gate.evaluar_pipeline(tmp, needs, {"semgrep"})
        self.assertIsNone(resultado["por_herramienta"]["codeql"])
        self.assertFalse(any(h["herramienta"] == "CodeQL" for h in resultado["hallazgos"]))


class EscapadoTests(unittest.TestCase):
    """El texto de los reportes puede traer rutas o mensajes con caracteres de control; deben salir escapados."""

    def test_escapar_markdown_neutraliza_pipes_y_angulos(self):
        texto = "a|b <script>alert(1)</script>\nsegunda linea\r\n"
        resultado = gate.escapar_markdown(texto)
        self.assertNotIn("|b", resultado.replace("\\|b", ""))  # el | real quedo escapado
        self.assertIn("\\|", resultado)
        self.assertNotIn("<script>", resultado)
        self.assertIn("&lt;script&gt;", resultado)
        self.assertNotIn("\n", resultado)
        self.assertNotIn("\r", resultado)

    def test_escapar_anotacion_neutraliza_porcentaje_y_saltos_de_linea(self):
        texto = "100% fallido\r\ncontinua en otra linea"
        resultado = gate.escapar_anotacion(texto)
        self.assertNotIn("\r", resultado)
        self.assertNotIn("\n", resultado)
        self.assertIn("%25", resultado)
        self.assertIn("%0D", resultado)
        self.assertIn("%0A", resultado)

    def test_hallazgo_con_caracteres_de_inyeccion_sale_escapado_en_el_resumen(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "dependency-check-report.json"
            vulns = [{
                "name": "CVE-INYECCION",
                "severity": "CRITICAL",
                "cvssv3": {"baseScore": 9.8},
            }]
            datos = _dependency_check(vulnerabilidades=vulns)
            datos["dependencies"][0]["fileName"] = "raro|<script>\nmalicioso.jar"
            _escribir_json(ruta, datos)
            hallazgos = gate.evaluar_dependency_check(ruta)
        resumen = gate.generar_resumen_markdown(
            {
                "fallos_previos": [],
                "reportes_faltantes": [],
                "hallazgos": hallazgos,
                "por_herramienta": {clave: [] for clave in gate.ORDEN_REPORTES},
            },
            set(),
        )
        self.assertNotIn("<script>", resumen)
        for linea in resumen.splitlines():
            # Ninguna linea de la tabla debe tener un "|" suelto fuera de los separadores de columna.
            self.assertNotIn("malicioso.jar\n", linea + "\n")


class ArgumentosDeLineaDeComandosTests(unittest.TestCase):

    def test_main_aprueba_contra_reportes_limpios(self):
        with tempfile.TemporaryDirectory() as tmp:
            _poblar_reportes_dir(tmp)
            needs_path = Path(tmp) / "needs.json"
            _escribir_json(needs_path, {"build-and-test": {"result": "success"}})
            resumen_path = Path(tmp) / "resumen.md"
            salida = gate.main([
                "--reportes-dir", tmp,
                "--needs-json", str(needs_path),
                "--resumen", str(resumen_path),
                "--requeridos", "semgrep,codeql,spotbugs,sbom-trivy,dependency-check",
            ])
            self.assertEqual(salida, gate.EXIT_OK)
            self.assertTrue(resumen_path.exists())
            self.assertIn("APROBADO", resumen_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
