# 🔒 Política de Seguridad (Español)

Este documento es el punto de entrada en español para reportes y políticas de seguridad del repositorio.

**Política canónica (fuente de verdad):** `../../SECURITY.md`

---

## Divulgación responsable

Si descubrís una vulnerabilidad de seguridad, **no la publiques en Issues públicas**. Reportala de forma privada usando el proceso indicado en `../../SECURITY.md`.

---

## Cómo reportar

Seguí el proceso descrito en: `../../SECURITY.md`

> Si el repositorio está en GitHub y está habilitado, también podés usar “Report a vulnerability” desde la pestaña **Security** (tal como describe la policy). [web:217]

---

## Qué reportar (checklist)

Incluí en tu reporte:
- Descripción clara del problema
- Ruta/archivo afectado (y líneas si aplica)
- Pasos para reproducir (si aplica)
- Impacto potencial (qué permite hacer / qué se compromete)
- Contexto del entorno (OS, versión, comandos, configuración), si aplica
- Mitigación sugerida (opcional)

---

## Scope (qué entra)

Reportá problemas que afecten:
- Recomendaciones dentro de las reglas (patrones que puedan inducir a una implementación insegura)
- Ejemplos “secure” que sean vulnerables o incompletos
- Automatizaciones/scripts (por ejemplo, generación de PDFs) que puedan exponer datos o ejecutar acciones peligrosas
- Referencias/compliance/OWASP/CWE incorrectas que lleven a decisiones de seguridad erróneas

Fuera de scope (en general):
- Vulnerabilidades de dependencias externas (reportarlas a sus mantenedores)
- Dudas de uso o soporte general (usar Discussions/Issues no privadas)

---

## Qué NO publicar

No incluyas en público:
- Exploits funcionales completos o PoCs listos para usar (mejor describir el vector)
- Credenciales reales, tokens, keys
- PII o datos sensibles
- Información de terceros

---

## Enlace directo

Abrí: `../../SECURITY.md`