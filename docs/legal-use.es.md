# Uso autorizado y consideraciones legales

> **ADVERTENCIA: utiliza esta herramienta únicamente sobre modelos, endpoints, cuentas, datos e infraestructuras propios o para los que tengas autorización expresa y vigente. No la uses para probar sistemas ajenos sin permiso.**

## Antes de ejecutar una prueba

1. **Obtén autorización previa y documentada.** Debe proceder del propietario o de una persona con facultades suficientes. Define por escrito los activos, modelos, endpoints, técnicas, fechas, límites de carga y personas de contacto autorizados.
2. **Limita el alcance.** Configura el escáner para apuntar exclusivamente a los endpoints incluidos en la autorización. No amplíes la prueba a redes, servicios, herramientas, cuentas o datos de terceros.
3. **No pruebes producción por defecto.** Prefiere modelos y entornos aislados, datos sintéticos y endpoints locales. Evita acciones destructivas, denegación de servicio, extracción de datos reales o cambios persistentes.
4. **Protege la evidencia.** Los informes pueden contener prompts, respuestas, nombres de modelos, direcciones de endpoints, fragmentos de datos sensibles o secretos que el modelo haya revelado. Restringe el acceso, cifra el almacenamiento cuando proceda, redacta secretos y establece plazos de conservación y borrado.
5. **Detén la prueba si sales del alcance**, observas efectos inesperados, accedes a datos no autorizados o recibes una petición de parada.

## Legislación: comprueba cada jurisdicción

La legalidad depende del país y, en ocasiones, de la región, del tipo de sistema, de los datos tratados, de la relación contractual y de la finalidad de la prueba. Antes de usar la herramienta, revisa la legislación aplicable **en cada país donde estén el operador, el propietario del sistema, la infraestructura y las personas cuyos datos puedan verse afectados**. Comprueba también las normas sectoriales, protección de datos, confidencialidad, propiedad intelectual, contratos, condiciones del proveedor y políticas internas.

No existe en este repositorio una certificación jurídica internacional ni una revisión exhaustiva y actualizada de la legislación de todos los países. Esta advertencia no es asesoramiento legal, no sustituye la autorización del propietario ni garantiza que una prueba concreta sea lícita. Si hay dudas, consulta a un profesional jurídico cualificado en las jurisdicciones pertinentes y al responsable de seguridad/privacidad de la organización.

## Límites técnicos

Local LLM Red Team es un banco de pruebas de comportamiento a nivel de prompt. Sus resultados heurísticos no demuestran por sí solos que haya existido acceso, exfiltración, ejecución de herramientas o modificación de sistemas. No debe conectarse a herramientas reales, credenciales de producción ni datos personales innecesarios. Un resultado PASS no certifica seguridad y NOT_DETECTED es inconcluso.

## Condiciones de uso responsable

Al ejecutar la herramienta, el operador asume la responsabilidad de verificar la autorización, el alcance, la base jurídica y las medidas de seguridad aplicables. Los autores y mantenedores no autorizan el acceso no consentido ni el uso ilícito de la herramienta. El software se proporciona «tal cual», conforme a la licencia del proyecto y sin garantía de idoneidad para un propósito jurídico o de seguridad específico.
