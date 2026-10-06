# Luna - API Security Scanner

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/Licencia-MIT-green.svg)](LICENSE)

> Escáner modular de seguridad para APIs REST, escrito en Python.

---

## Descripción

Creé **Luna** porque necesitaba una herramienta rápida, modular y directa para auditar la seguridad de APIs REST durante mis pruebas de penetración. Me cansé de andar saltando entre diez herramientas distintas para verificar headers, probar XSS reflejado, inyecciones SQL, problemas de IDOR y autenticación rota. Quería algo que pudiera correr desde la terminal, que me diera resultados claros y que me dejara elegir exactamente qué módulos ejecutar según lo que necesitara en cada momento.

Luna no pretende ser un reemplazo de Burp Suite ni de ninguna suite profesional completa. Es una herramienta complementaria que te permite automatizar las verificaciones más comunes de seguridad en APIs de forma rápida y repetible. La diseñé pensando en pentesters, bug bounty hunters y desarrolladores que quieren validar la seguridad de sus endpoints antes de mandarlos a producción.

---

## Aviso Importante

> **Luna es una herramienta de asistencia automatizada y NO reemplaza una auditoría de seguridad manual realizada por un profesional.**
>
> Los resultados que genera son orientativos. Siempre tenés que validar los hallazgos manualmente y complementar con pruebas adicionales. Un escaneo automatizado nunca va a cubrir el 100% de los vectores de ataque posibles.

---

## Módulos

| Módulo | Archivo | Descripción |
|--------|---------|-------------|
| `headers` | `luna/modules/headers.py` | Verifica la presencia y configuración de headers de seguridad HTTP. Comprueba HTTPS, HSTS, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options y más. |
| `xss` | `luna/modules/xss.py` | Detecta vulnerabilidades de Cross-Site Scripting (XSS) reflejado inyectando payloads en los parámetros de la URL y analizando las respuestas. |
| `sqli` | `luna/modules/sqli.py` | Prueba inyección SQL basada en errores. Envía payloads maliciosos y busca mensajes de error de bases de datos en las respuestas. |
| `idor` | `luna/modules/idor.py` | Detecta referencias directas a objetos inseguras (IDOR) comparando respuestas entre IDs válidos e inválidos para identificar problemas de control de acceso. |
| `auth` | `luna/modules/auth.py` | Evalúa la seguridad de la autenticación basada en tokens Bearer. Prueba endpoints con tokens válidos, inválidos y sin token. |

---

## Requisitos

- Python 3.8 o superior
- pip (gestor de paquetes de Python)

### Dependencias

Las dependencias se instalan automáticamente desde `requirements.txt`:

```
requests
```

---

## Instalación

```bash
# Cloná el repositorio
git clone https://github.com/AlanNewberry/Luna.git
cd Luna

# (Opcional) Creá un entorno virtual
python -m venv venv
source venv/bin/activate

# Instalá las dependencias
pip install -r requirements.txt
```

---

## Uso

### Sintaxis general

```bash
python -m luna <URL> [opciones]
```

### Escaneo completo (todos los módulos)

```bash
python -m luna https://api.ejemplo.com/v1/users
```

### Seleccionar módulos específicos

Podés elegir qué módulos ejecutar con `--modules`:

```bash
# Solo verificar headers de seguridad
python -m luna https://api.ejemplo.com/v1/users --modules headers

# Headers y XSS
python -m luna https://api.ejemplo.com/v1/users --modules headers,xss

# Solo inyección SQL
python -m luna https://api.ejemplo.com/v1/users --modules sqli
```

### Pruebas de IDOR

Para probar IDOR necesitás indicar el parámetro a testear, un valor válido y uno inválido:

```bash
python -m luna https://api.ejemplo.com/v1/users/{id}/profile \
  --modules idor \
  --param {id} \
  --valid-value 1 \
  --invalid-value 9999
```

Esto va a comparar las respuestas entre el ID válido y el inválido para detectar si existe control de acceso sobre el recurso.

### Pruebas de autenticación

Para evaluar la seguridad de autenticación Bearer, pasale el token con `--token`:

```bash
python -m luna https://api.ejemplo.com/v1/protected/resource \
  --modules auth \
  --token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

El módulo va a probar:
- Acceso con el token válido proporcionado
- Acceso con un token inválido/modificado
- Acceso sin token (para verificar que el endpoint rechaza solicitudes no autenticadas)

### Payloads personalizados

Podés usar tus propios archivos de payloads para XSS e inyección SQL:

```bash
# Payloads personalizados de SQL injection
python -m luna https://api.ejemplo.com/v1/search \
  --modules sqli \
  --sql-payloads /ruta/a/mis-payloads-sql.txt

# Payloads personalizados de XSS
python -m luna https://api.ejemplo.com/v1/search \
  --modules xss \
  --xss-payloads /ruta/a/mis-payloads-xss.txt
```

### Escaneo en paralelo de múltiples endpoints

Podés escanear varios endpoints a la vez con `--parallel`:

```bash
python -m luna https://api.ejemplo.com/v1/users \
  --parallel https://api.ejemplo.com/v1/products https://api.ejemplo.com/v1/orders \
  --modules headers,xss,sqli
```

### Salida en formato JSON

Para exportar los resultados a JSON (útil para integración con otras herramientas o pipelines de CI/CD):

```bash
# Salida JSON en la consola
python -m luna https://api.ejemplo.com/v1/users --output json

# Guardar resultados en un archivo
python -m luna https://api.ejemplo.com/v1/users --output json > resultados.json
```

### Ejemplo completo

```bash
python -m luna https://api.ejemplo.com/v1/users/{id}/profile \
  --modules headers,xss,sqli,idor,auth \
  --param {id} \
  --valid-value 1 \
  --invalid-value 9999 \
  --token eyJhbGciOiJIUzI1NiJ9... \
  --sql-payloads payloads/sqli.txt \
  --xss-payloads payloads/xss.txt \
  --output json
```

---

## Estructura del Proyecto

```
Luna/
├── luna/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── scanner.py          # Motor principal del escáner
│   │   └── findings.py         # Modelo de hallazgos y severidades
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── headers.py          # Verificación de headers de seguridad
│   │   ├── xss.py              # Detección de XSS reflejado
│   │   ├── sqli.py             # Inyección SQL basada en errores
│   │   ├── idor.py             # Detección de IDOR
│   │   └── auth.py             # Pruebas de autenticación Bearer
│   └── reporting/
│       ├── __init__.py
│       ├── json_report.py      # Generador de reportes JSON
│       └── console.py          # Generador de reportes en consola
├── tests/
│   ├── test_auth.py
│   ├── test_headers.py
│   ├── test_sqli.py
│   ├── test_xss.py
│   └── test_findings.py
├── requirements.txt
├── LICENSE
└── README.md
```

---

## Tests

Ejecutá los tests con `pytest`:

```bash
# Ejecutar todos los tests
python -m pytest tests/ -v

# Ejecutar tests de un módulo específico
python -m pytest tests/test_headers.py -v
python -m pytest tests/test_sqli.py -v
python -m pytest tests/test_xss.py -v
python -m pytest tests/test_auth.py -v
python -m pytest tests/test_findings.py -v
```

---

## Limitaciones

- **XSS:** Solo detecta XSS reflejado. No cubre XSS almacenado ni basado en DOM.
- **SQL Injection:** Detecta inyección basada en errores únicamente. No cubre inyección ciega (blind), basada en tiempo ni técnicas de extracción avanzadas.
- **IDOR:** Requiere que le indiques manualmente los valores de parámetros a probar. No descubre automáticamente recursos enumerables.
- **Auth:** Se limita a pruebas de tokens Bearer. No cubre otros esquemas de autenticación como OAuth flows completos, API keys en headers personalizados, etc.
- **Rate limiting:** No implementa mecanismos de rate limiting propios. Tené cuidado de no saturar los endpoints que estés testeando.
- **WAF:** Algunas configuraciones de WAF (Web Application Firewall) pueden bloquear los payloads y producir falsos negativos.
- **Cobertura general:** Esto es un escáner automatizado básico. Siempre complementá con pruebas manuales y herramientas especializadas.

---

## Aviso Legal

**Luna fue desarrollada exclusivamente con fines educativos y para pruebas de seguridad autorizadas.**

El uso de esta herramienta contra sistemas sin autorización explícita del propietario es **ilegal** y va en contra de los principios del hacking ético. Yo no me hago responsable del mal uso que se le pueda dar a esta herramienta.

Antes de usar Luna contra cualquier objetivo:

1. Asegurate de tener **autorización escrita** del propietario del sistema.
2. Usala solo dentro del **alcance definido** en tu acuerdo de pruebas.
3. Reportá de manera responsable cualquier vulnerabilidad que encuentres.

---

## Autor

**Alan Newberry** (alias `44Viciius`)

---

## Licencia

Este proyecto está licenciado bajo la [Licencia MIT](LICENSE). Podés usarlo, modificarlo y distribuirlo libremente.
