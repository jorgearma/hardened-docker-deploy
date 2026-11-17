# 4. Impacto demostrado

Qué permite cada hallazgo en la práctica, probado solo contra mi propio VPS. Describo el **impacto y la cadena de ataque**, no una receta paso a paso.

## H-01

- **Supuesto de partida:** p. ej. "el atacante ya tiene ejecución de código en la app".
- **Qué consigue gracias al hallazgo:**
- **Qué control lo habría impedido:**
- **Evidencia:** [`evidencias/antes/`](evidencias/antes/)

## Cadena de ataque completa

Cómo se combinan los hallazgos (p. ej. H-02 da el acceso inicial → H-01 permite persistir → H-03 permite salir al host).

```text
acceso inicial → … → impacto final
```
