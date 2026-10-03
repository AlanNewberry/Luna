# Luna - API Security Scanner

Luna es una herramienta de linea de comandos liviana para ejecutar chequeos de seguridad automatizados basicos contra APIs web. Prueba patrones de vulnerabilidades comunes incluyendo IDOR, autenticacion debil, SQL Injection, XSS y configuraciones incorrectas de HTTPS/HSTS.

## Aviso importante

Luna realiza chequeos basicos y superficiales. No reemplaza pruebas de penetracion manuales, auditorias de seguridad profesionales ni herramientas de escaneo de nivel productivo. Los resultados pueden incluir falsos positivos y con seguridad van a pasar por alto vulnerabilidades que requieren un analisis mas profundo.

Solo usa Luna contra sistemas que sean de tu propiedad o para los que tengas autorizacion escrita explicita. El escaneo no autorizado es ilegal en la mayoria de las jurisdicciones.

## Instalacion

```bash
pip install -r requirements.txt
```

## Uso

Escaneo basico:

```bash
python -m luna https://api.example.com/endpoint
```

Seleccionar modulos especificos:

```bash
python -m luna https://api.example.com/endpoint --modules headers,xss,sqli
```

Salida en JSON:

```bash
python -m luna https://api.example.com/endpoint --output json
```

Testing de IDOR:

```bash
python -m luna https://api.example.com/users/{id} --modules idor --param {id} --valid-value 1 --invalid-value 9999
```

Testing de autenticacion:

```bash
python -m luna https://api.example.com/protected --modules auth --token eyJhbGciOi...
```

Payloads personalizados:

```bash
python -m luna https://api.example.com/search --modules sqli --sql-payloads "' OR 1=1" "'; DROP TABLE x;"
python -m luna https://api.example.com/search --modules xss --xss-payloads "<script>alert(1)</script>"
```

Escaneo en paralelo:

```bash
python -m luna https://api1.example.com --parallel https://api2.example.com https://api3.example.com
```

## Modulos

| Modulo    | Descripcion                                                  |
|-----------|--------------------------------------------------------------|
| `headers` | Verifica el uso de HTTPS y la presencia del header HSTS      |
| `xss`     | Prueba XSS reflejado inyectando payloads de script           |
| `sqli`    | Prueba SQL Injection mediante deteccion basada en errores    |
| `idor`    | Verifica referencias directas a objetos inseguras            |
| `auth`    | Prueba las respuestas del endpoint a un bearer token dado    |

## Limitaciones

- La deteccion es basica y basada en patrones. No va a encontrar blind SQL Injection, stored XSS ni fallas de logica.
- Los chequeos de IDOR se basan en comparar codigos de estado HTTP, que es una heuristica aproximada.
- La deteccion de XSS solo cubre payloads reflejados en el cuerpo de la respuesta.
- No hay automatizacion de flujos de autenticacion, manejo de sesiones ni manejo de cookies.
- No tiene rate limiting ni throttling. Usa con responsabilidad.

## Estructura del proyecto

```
luna/
    __init__.py
    __main__.py
    cli.py
    core/
        findings.py
        scanner.py
    modules/
        headers.py
        xss.py
        sqli.py
        idor.py
        auth.py
    reporting/
        json_report.py
        console.py
tests/
    test_findings.py
    test_headers.py
```

## Creditos

Desarrollado originalmente por Alan Newberry bajo el alias `44Viciius`.
