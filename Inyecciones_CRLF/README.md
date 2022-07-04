# Expansión de Alcance para Inyecciones CRLF (Carriage Return Line Feed)

En E-Virtus realizamos una investigación con el objetivo de generar diccionarios únicos y nuevos con diferentes tipos de payloads para Inyecciones CRLF, considerando casos prácticos y válidos, apoyándonos en registros públicos de códigos CVE y disclosure técnico de reportes en la plataforma de bug bounty HackerOne.

El repositorio contiene 1 diccionario con un total de 383 payloads para inyección CRLF, validados mediante la reproducción del registro CVE-2020-7695, una inyección CRLF en el servidor web de tipo ASGI Uvicorn.

* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7695
* https://security.snyk.io/vuln/SNYK-PYTHON-UVICORN-570471

También contiene una plantilla Yaml para ser utilizada con Nuclei

* https://github.com/projectdiscovery/nuclei

Todos los detalles relacionados a estas pequeña investigación, pueden ser revisados en los siguientes enlaces:

* e-vurtus.blog.link
* linkedin.pulse.link

## Utilización básica de CRLF en lenguajes de programación

| Nombre     | Abreviación | Carácter | Hexadecimal | ASCII |
| ----------- | ----------- | ----------- | ----------- | ----------- |
| Carriage Return | CR | \n | 0D | %0D |
| Line Feed | LF | \n | 0A | %0A |

## Casos públicos de Inyección CRLF en HackerOne

| Descripción      | URL |
| ----------- | ----------- |
| Parámetros en URL como entry-points      | https://hackerone.com/reports/446271       |
| Bypass de filtro CRLF utilizando codificación UTF-8 basada en Unicode   | https://hackerone.com/reports/217058        |
| Utilización de Tab Horizontal (HT) como complemento del payload (\t)   | https://hackerone.com/reports/217058        |
| Uso del caracter ? como entry-point de parámetros en URL   | https://hackerone.com/reports/192667        |
| Uso del caracter ? como entry-point de parámetros en URL sin LF (%0a)   | https://hackerone.com/reports/145128        |
| Adición de espacios como complemento del payload (%20)   | https://hackerone.com/reports/13314        |
| Uso individual de Carriage Return (CR) para inyecciones   | https://hackerone.com/reports/67386        |
| Uso individual de Line Feed (LF) para inyecciones   | https://hackerone.com/reports/66386        |
| Payload de inyección en Mayúsculas   | https://hackerone.com/reports/730786        |
| Inyección CRLF como inyección de HTML   | https://hackerone.com/reports/121489        |
| Inyección CRLF como inyección de HTML   | https://hackerone.com/reports/183796        |
| Bypass de X-XSS-Protection header   | https://hackerone.com/reports/192749        |
| Uso de # (%23) como complemento del payload sin LF (%0a)   | https://hackerone.com/reports/154306        |
| Inyección CRLF en valores de parámetros mediante método HTTP POST   | https://hackerone.com/reports/181939        |
| Cross-site Scripting (XSS) usando payload de esquema Data URL (HTML)   | https://hackerone.com/reports/177624        |
| Inyección de CRLF mediante HTTP headers   | https://hackerone.com/reports/798686        |
| enegación de Servicios (DoS)   | https://hackerone.com/reports/583819        |
| Inyección de CRLF en rutas de directorios   | https://hackerone.com/reports/143139        |
| Bypass de comentarios en JavaScript   | https://hackerone.com/reports/221883        |
| Bug Chaining   | https://hackerone.com/reports/441090        |
| Bug Chaining   | https://hackerone.com/reports/513236        |
| Uso del caracter + como reemplazo de CRLF   | https://hackerone.com/reports/53843        |

## Colección básica de carácteres para inyección CRLF

| Nombre      | Abreviación | Carácter | Hexadecimal | ASCII | Tipo |
| ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
| Carriage Return      | CR       | \r       | 0D       | %0D       | Raíz       |
| Line Feed   | LF        | \n       | 0A       | %0A       | Raíz       |

## Colección de carácteres usando HackerOne como fuente

| Nombre      | Abreviación | Carácter | Hexadecimal | ASCII | Tipo |
| ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
| Hash      |        | #       | 23       | %23       | Prefijo       |
| Question mark   |         | ?       | 3F       | %3F       | Prefijo       |
| Horizontal Tab   | HT        | \t       | 09       | %09       | Sufijo       |
| Space   |         |        | 20       | %20       | Sufijo       |

## Bypass de filtro CRLF utilizando codificación UTF-8 para Unicode

| Nombre      | Payload | Descripción | Tipo |
| ----------- | ----------- | ----------- | ----------- |
| CRLF Bypass      | %E5%98%8A%E5%98%8D       | ASCII (mayúsculas)       | Raíz       |
| CRLF Bypass   | %e5%98%8a%e5%98%8d        | ASCII (minúsculas)       | Raíz       |

## Colección de carácteres basados en factores de combinación

| Nombre      | Abreviación | Carácter | Hexadecimal | ASCII | Tipo |
| ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
| Vertical Tab      | VTAB       | \v       | 0B       | %0B       | Sufijo       |
| Form Feed   | FF        | \f       | 0C       | %0C       | Sufijo       |
| Null   | NUL        | \0       | 00       | %00       | Ambivalente       |

## Matrices para la generación de payloads

| Factor      |
| ----------- | 
| URL encode y double encode      |
| Uso de mayúsculas y minúsculas   |

|       | Combinación |
| ----------- | ----------- |
| 1      | Raíz en mayúsculas y minúsculas       |
| 2   | Raíz + double encode en mayúsculas y minúsculas        |
| 3   | Prefijo + raíz en mayúsculas y minúsculas        |
| 4   | Prefijo + raíz + double encode en mayúsculas y minúsculas        |
| 5   | Raíz + sufijo en mayúsculas y minúsculas        |
| 6   | Raíz + sufijo + double encode en mayúsculas y minúsculas        |
| 7   | Prefijo + raíz + sufijo en mayúsculas y minúsculas        |
| 8   | Prefijo + raíz + sufijo + double encode en mayúsculas y minúsculas        |

| Prefijo      | Sufijo |
| ----------- | ----------- |
| Foo      | pwned:foo       |
| Foo   | pwned%3Afoo        |
| Foo   | pwned%3afoo        |
| Foo   | pwned:%20foo        |
| Foo   | pwned%3A%20foo        |
| Foo   | pwned%3a%20foo        |

## Créditos

Laboratorio de Ciberseguridad y Research. E-Virtus Lab 2022
