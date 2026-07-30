# Architecture Decision Records (ADR)

Este documento recoge las principales decisiones de arquitectura adoptadas durante el desarrollo de Praevia.

Cada ADR documenta una decisión considerada estable, junto con su justificación, con el objetivo de mantener la coherencia del proyecto.

## Índice

- ADR-001 · Objetivo de Praevia
- ADR-002 · Arquitectura modular
- ADR-003 · Separación entre código e informes
- ADR-004 · Entorno de desarrollo
- ADR-005 · Responsabilidad de `main.py`
- ADR-006 · Organización de la CLI
- ADR-007 · Modelo de dominio interno
- ADR-008 · Los collectors representan dominios de información
- ADR-009 · Responsabilidad de los collectors
- ADR-010 · Flujo de procesamiento
- ADR-011 · Estado compartido del reconocimiento
- ADR-012 · El modelo de dominio representa el conocimiento, no el procesamiento
- ADR-013 · Priorización basada en recomendaciones de investigación


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

---

## ADR-007 · Modelo de dominio interno

**Estado:** Aceptado

Cada collector traducirá la información obtenida de su fuente OSINT al modelo de dominio interno de Praevia antes de devolver cualquier resultado.

El resto de la aplicación trabajará exclusivamente con estos modelos internos y nunca dependerá directamente de las respuestas o formatos propios de las fuentes externas.

Algunos ejemplos de modelos de dominio son `Technology`, `Subdomain`, `Repository`, `Certificate` o `HistoricalURL`.

**Justificación**

Cada fuente OSINT expone la información con formatos y estructuras diferentes. Traducir estos datos dentro de cada collector desacopla la lógica interna de Praevia de las particularidades de cada fuente, facilita la incorporación o sustitución de nuevos collectors y permite que el análisis y la generación de informes trabajen siempre sobre un modelo de datos homogéneo.

---

## ADR-008 · Los collectors representan dominios de información

**Estado:** Aceptado

Los collectors de Praevia representan dominios funcionales del reconocimiento pasivo y no herramientas o fuentes OSINT concretas.

Cada collector responde a una pregunta relevante para el pentester y puede utilizar una o varias fuentes de información para construir su resultado.

La versión inicial de Praevia implementa los siguientes collectors:

- `Technology Fingerprinting`
- `Asset Discovery`
- `Wayback Machine`
- `GitHub Intelligence`
- `Public Web Resources`

Las fuentes concretas empleadas por cada collector podrán modificarse o ampliarse sin afectar a la arquitectura de la aplicación.

**Justificación**

Diseñar los collectors como capacidades funcionales desacopla la arquitectura de herramientas específicas y facilita la incorporación de nuevas fuentes OSINT en el futuro. El pentester trabaja con dominios de información, no con APIs concretas.

---

## ADR-009 · Responsabilidad de los collectors

**Estado:** Aceptado

Cada collector es responsable de obtener toda la información correspondiente a su dominio funcional, incluyendo el enriquecimiento específico que resulte necesario para generar un resultado útil.

Este enriquecimiento forma parte de la responsabilidad natural del collector y no constituye una fase independiente de la arquitectura.

Por ejemplo, `Technology Fingerprinting` podrá complementar las tecnologías detectadas con información procedente de bases públicas como CVE, KEV, EPSS o PoCs cuando dicha información aporte contexto al pentester.

**Justificación**

Separar el enriquecimiento en una capa independiente introduciría complejidad innecesaria y rompería la cohesión de los collectors. Mantener toda la lógica relacionada con un mismo dominio dentro del mismo módulo simplifica la arquitectura y favorece su mantenimiento.

---

## ADR-010 · Flujo de procesamiento

**Estado:** Aceptado

La arquitectura de Praevia sigue el siguiente flujo de procesamiento:

```text
CLI
 │
 ▼
Target
 │
 ▼
Collectors
 │
 ├── Technology Fingerprinting
 │
 ├── Asset Discovery
 │
 ├── Wayback Machine
 │
 ├── GitHub Intelligence
 │
 └── Public Web Resources
 │
 ▼
Correlation Engine
 │
 ▼
Investigation Prioritizer
 │
 ▼
Report Generator
 │
 ▼
Exporters
```

Los collectors generan información estructurada sobre el objetivo utilizando una o varias fuentes OSINT.

El `Correlation Engine` relaciona la información procedente de los distintos collectors, elimina duplicidades y genera una visión unificada del reconocimiento.

Posteriormente, el `Investigation Prioritizer` transforma dicha información en líneas de investigación recomendadas para orientar la fase activa del pentesting.

Finalmente, el `Report Generator` organiza los hallazgos y los entrega a los distintos exportadores.

**Justificación**

Separar la obtención de información, la correlación y la priorización permite mantener responsabilidades claramente diferenciadas y convertir los datos recopilados en información accionable para el pentester.

---

# ADR-011 · Estado compartido del reconocimiento

**Estado:** Aceptado

Praevia utilizará un único objeto compartido denominado `ReconnaissanceData` para representar el estado completo del reconocimiento durante toda la ejecución.

Los collectors incorporarán a este estado las entidades descubiertas junto con sus evidencias. Los módulos posteriores consumirán y enriquecerán el mismo objeto, sin generar representaciones alternativas de la información.

`ReconnaissanceData` constituirá la única fuente de verdad (*Single Source of Truth*) del conocimiento obtenido durante el proceso de reconocimiento.

**Justificación**

Mantener un único estado compartido simplifica la comunicación entre componentes, facilita la correlación y deduplicación de información, preserva la trazabilidad mediante las evidencias y favorece la extensibilidad de la herramienta al permitir incorporar nuevos collectors sin modificar el flujo de procesamiento.

---

## ADR-012 · El modelo de dominio representa el conocimiento, no el procesamiento

**Estado:** Aceptado

El modelo de dominio de Praevia representa exclusivamente el conocimiento obtenido durante el reconocimiento pasivo y las recomendaciones generadas a partir de dicho conocimiento.

Las entidades del dominio no almacenan información relacionada con el funcionamiento interno de los algoritmos utilizados durante el procesamiento, como puntuaciones temporales, reglas evaluadas o estados intermedios.

Los componentes encargados del análisis podrán utilizar información auxiliar durante la ejecución, pero únicamente producirán objetos del dominio una vez finalizado el procesamiento.

**Justificación**

Separar el modelo de dominio de la lógica interna de procesamiento evita acoplar la estructura de datos a una implementación concreta del algoritmo de priorización. Esto facilita modificar o sustituir dicho algoritmo sin afectar al resto de la aplicación ni a los exportadores.

---

## ADR-013 · Priorización basada en recomendaciones de investigación

**Estado:** Aceptado

Praevia prioriza líneas de investigación y no vulnerabilidades.

El `Investigation Prioritizer` analiza la información correlacionada obtenida durante el reconocimiento pasivo para generar recomendaciones ordenadas que orienten las siguientes fases del pentesting.

Las prioridades asignadas (`HIGH`, `MEDIUM` y `LOW`) representan únicamente la conveniencia relativa de investigar cada línea propuesta y no constituyen una evaluación del riesgo o de la criticidad de una vulnerabilidad.

**Justificación**

El reconocimiento pasivo no proporciona información suficiente para determinar la existencia o severidad de vulnerabilidades. Limitar la priorización a recomendaciones de investigación mantiene el alcance de Praevia alineado con la naturaleza de los datos disponibles y evita transmitir una falsa sensación de precisión.

---