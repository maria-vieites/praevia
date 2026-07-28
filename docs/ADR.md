# Architecture Decision Records (ADR)

Este documento recoge las principales decisiones de arquitectura adoptadas durante el desarrollo de Praevia.

Cada ADR documenta una decisión considerada estable, junto con su justificación, con el objetivo de mantener la coherencia del proyecto.

---

## ADR-001 · Objetivo de Praevia

**Estado:** Aceptado

Praevia es una herramienta de reconocimiento pasivo (OSINT) orientada al pentesting de aplicaciones web.

Recopila, organiza y correlaciona información obtenida exclusivamente mediante técnicas pasivas para apoyar la fase de reconocimiento inicial.

La herramienta no realiza escaneo activo, explotación ni validación de vulnerabilidades, ni asigna niveles de riesgo. En su lugar, proporciona contexto y recomendaciones para orientar las fases posteriores del pentesting.

**Justificación**

Definir claramente el alcance de la herramienta evita ampliar sus responsabilidades más allá de los objetivos del proyecto.

---

## ADR-002 · Arquitectura modular

**Estado:** Aceptado

Praevia se organiza mediante una arquitectura modular, donde cada componente tiene una única responsabilidad.

Estructura inicial:

- `collectors/` → Obtención de información OSINT.
- `core/` → Procesamiento y lógica de negocio.
- `exporters/` → Generación de informes.
- `config/` → Configuración.
- `utils/` → Funciones auxiliares.
- `reports/` → Informes generados.
- `docs/` → Documentación.
- `tests/` → Pruebas.

**Justificación**

Una arquitectura modular mejora la mantenibilidad, reutilización y escalabilidad del proyecto.

---

## ADR-003 · Separación entre código e informes

**Estado:** Aceptado

Praevia distingue entre:

- `exporters/` → Código encargado de generar informes.
- `reports/` → Informes producidos durante la ejecución.

**Justificación**

Separar el código fuente de los resultados generados mantiene el proyecto organizado.

---

## ADR-004 · Entorno de desarrollo

**Estado:** Aceptado

El proyecto se desarrolla utilizando:

- Python 3.12.10
- Entorno virtual (`.venv`)
- Visual Studio Code
- Git
- GitHub

Las dependencias se gestionan mediante `requirements.txt`.

**Justificación**

Utilizar un entorno de desarrollo reproducible facilita la colaboración y el mantenimiento.

---

## ADR-005 · Responsabilidad de `main.py`

**Estado:** Aceptado

`main.py` constituye el punto de entrada de Praevia y únicamente coordina el flujo general de ejecución de la aplicación.

Toda la lógica de negocio se delega en los módulos correspondientes.

**Justificación**

Mantener un punto de entrada ligero favorece la separación de responsabilidades.

---

## ADR-006 · Organización de la interfaz de línea de comandos

**Estado:** Aceptado

La interfaz de línea de comandos se implementa mediante `argparse` y su configuración se centraliza en el paquete `cli`.

Actualmente, este paquete contiene `parser.py`, responsable de crear y configurar el `ArgumentParser`. Los futuros componentes relacionados con la CLI también se incorporarán a este paquete.

**Justificación**

Centralizar la lógica de la interfaz mejora la organización del proyecto y mantiene `main.py` libre de detalles de implementación.