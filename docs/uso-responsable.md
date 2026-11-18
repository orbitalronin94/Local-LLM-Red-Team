# Uso responsable y aviso legal

Local LLM Red Team es una herramienta de pruebas de seguridad. Se ofrece para investigación, formación y evaluaciones realizadas de forma lícita y con autorización expresa.

## La autorización es obligatoria

**Prueba únicamente modelos, endpoints, sistemas y datos que sean tuyos o cuyo análisis tengas expresamente autorizado. No utilices esta herramienta contra sistemas de otra persona u organización sin permiso previo y explícito.** Que un sistema sea accesible desde Internet, esté expuesto públicamente o pueda probarse técnicamente no significa que tengas permiso para hacerlo.

Antes de cada evaluación:

1. Obtén autorización escrita de la persona u organización propietaria del sistema e identifica quién la concede.
2. Define el alcance exacto: dominios, direcciones IP, puertos, endpoints API, modelos, cuentas, ventana temporal, técnicas permitidas, límites de peticiones y acciones prohibidas.
3. Comprueba que la autorización cubre las pruebas automatizadas o adaptativas y los prompts, payloads y volúmenes de tráfico concretos.
4. Utiliza un entorno de pruebas dedicado y datos sintéticos siempre que sea posible. No introduzcas datos personales reales, credenciales, secretos ni contenido confidencial de terceros.
5. Mantén los endpoints privados, utiliza credenciales de prueba con privilegios mínimos, fija límites conservadores y monitoriza el sistema.
6. Detén la prueba inmediatamente si el tráfico alcanza un sistema fuera de alcance, provoca efectos inesperados, afecta a la disponibilidad o revela datos a los que no tienes autorización de acceso.
7. Conserva las evidencias de forma segura y elimina secretos y datos personales antes de compartir informes.

## Comprueba la legislación de todas las jurisdicciones pertinentes

La normativa aplicable a las pruebas de seguridad varía entre países y también puede cambiar según el estado, provincia o región. Puede depender del lugar donde se encuentre quien realiza la prueba, de la ubicación del sistema y de su propietario, de dónde estén las personas cuyos datos se tratan y de dónde se aloje la infraestructura.

**Es responsabilidad de quien utiliza la herramienta comprobar, antes de ejecutar cualquier prueba, las leyes y normas aplicables en todas las jurisdicciones pertinentes.** Entre otras, pueden resultar relevantes las normas sobre acceso no autorizado o delitos informáticos, privacidad y protección de datos personales, confidencialidad e interceptación de comunicaciones, obligaciones de ciberseguridad, contratos, relaciones laborales y requisitos sectoriales. Revisa también las condiciones del proveedor, las políticas internas y los acuerdos con terceros.

Este repositorio no ofrece asesoramiento jurídico, no concede autorización para probar ningún sistema ni certifica que un uso concreto sea legal. Si el alcance o la base jurídica no están claros, no ejecutes la prueba hasta obtener autorización escrita suficiente y asesoramiento jurídico cualificado.

## Alcance técnico y limitaciones

El flujo predeterminado del proyecto está diseñado para inferencia local. Sin embargo, la CLI admite endpoints HTTP y compatibles con OpenAI configurables; si eliges un endpoint remoto, puedes enviarle prompts y tráfico generado. Verifica el destino y la autorización antes de ejecutar. Los hallazgos a nivel de prompt no demuestran que se haya ejecutado una herramienta externa ni que se haya producido un efecto real.

## Ausencia de garantía

El software se proporciona «tal cual», sin garantías. La persona usuaria es responsable de la configuración, el alcance de las pruebas, las salvaguardas operativas, el cumplimiento normativo y las consecuencias de su utilización.
