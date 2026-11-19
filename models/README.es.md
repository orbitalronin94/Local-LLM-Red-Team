# Recursos de modelos locales y kit de benchmark

Modelos GGUF pequeños para pruebas reproducibles de inferencia local. Los pesos se descargan bajo demanda y no se guardan en el repositorio.

| ID | Familia / repositorio GGUF | Parámetros | Cuantización | Tamaño aprox. | Licencia |
| --- | --- | ---: | --- | ---: | --- |
| smollm2 | [SmolLM2](https://huggingface.co/bartowski/SmolLM2-360M-Instruct-GGUF) | 360M | Q4_K_M | 271 MB | Apache-2.0 |
| qwen2_5 | [Qwen2.5](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF) | 0,5B | Q4_K_M | 491 MB | Apache-2.0 |
| llama3_2_1b | [Llama 3.2](https://huggingface.co/bartowski/Llama-3.2-1B-Instruct-GGUF) | 1B | Q4_K_M | 808 MB | Llama 3.2 Community License |
| gemma3_1b | [Gemma 3](https://huggingface.co/bartowski/google_gemma-3-1b-it-GGUF) | 1B | Q4_K_M | 806 MB | Gemma Terms |
| qwen2_5_3b | [Qwen2.5 3B](https://huggingface.co/bartowski/Qwen2.5-3B-Instruct-GGUF) | 3B | Q4_K_M | 1,93 GB | Apache-2.0 |
| llama3_2_3b | [Llama 3.2 3B](https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF) | 3B | Q4_K_M | 2,02 GB | Llama 3.2 Community License |
| gemma3_4b | [Gemma 3 4B](https://huggingface.co/ggml-org/gemma-3-4b-it-GGUF) | 4B | Q4_K_M | 2,49 GB | Gemma Terms |

Los GGUF son cuantizaciones comunitarias. Cada entrada identifica el repositorio cuantizado y el modelo original. Llama y Gemma tienen condiciones propias: consulta las tarjetas y licencias upstream antes de redistribuir o usar comercialmente. SmolLM2 está orientado principalmente al inglés; Qwen2.5 es multilingüe. No extrapoles una puntuación de un idioma a otro.

## Descarga e integridad

Desde la raíz del repositorio:

```bash
python scripts/download_models.py --list
python scripts/download_models.py --model llama3_2_1b
python scripts/download_models.py --model smollm2
python scripts/download_models.py --model qwen2_5
python scripts/download_models.py --model llama3_2_1b
python scripts/download_models.py --model gemma3_1b
python scripts/download_models.py --model qwen2_5_3b
python scripts/download_models.py --model llama3_2_3b
python scripts/download_models.py --model gemma3_4b
python scripts/download_models.py --model all
```

Instala la dependencia con `python -m pip install -e ".[models]"`. El descargador usa `huggingface_hub.hf_hub_download`, copia a un archivo temporal `.part`, comprueba un tamaño mínimo plausible y mueve el archivo de forma atómica a `models/weights/`. Escribe un `.metadata.json` con repositorio, revisión solicitada, bytes, fecha, backend y SHA-256. Usa `--force` para reemplazar un modelo y `--dry-run` para mostrar el destino sin descargar.

La revisión predeterminada es `main`. Para reproducibilidad estricta, conserva los metadatos y fija una revisión upstream inmutable antes de un benchmark formal. Los pesos están excluidos de Git; nunca subas pesos ni claves API.

## Servir con llama.cpp

Instala por separado una versión actual de `llama-server`:

```bash
llama-server --model models/weights/Llama-3.2-1B-Instruct-Q4_K_M.gguf --host 127.0.0.1 --port 8080
```

Ejecuta el destino compatible con OpenAI:

```bash
mkdir -p reports
python redteam.py --target openai --url http://127.0.0.1:8080/v1 --model local-model --db reports/llama-static.db --json reports/llama-static.json --report reports/llama-static.md
```

Mantén constantes versión del escáner, manifiesto, versión de llama.cpp, contexto, muestreo, hardware y flags. Compara IDs y evidencias individuales, no solo tasas agregadas.

## Interpretación

Son modelos compactos para pruebas de humo, no un benchmark representativo ni una afirmación de que una familia sea segura o insegura. El detector es heurístico. `PASS`, `FAIL` y `NOT_DETECTED` son señales de triaje; revisa respuestas originales y solicita revisión independiente para conclusiones importantes.

## Cribado rápido preliminar

El mismo workflow permite seleccionar `benchmark_profile=quick` al lanzarlo manualmente. Elige **Actions → Local model red-team benchmark → Run workflow → quick** para una primera prueba de humo o para recibir feedback más rápido durante el desarrollo. Quick ejecuta una muestra fija de ocho ataques con un límite de 192 tokens por respuesta y omite los escenarios multi-turno deterministas, las pruebas emparejadas EN/ES y la matriz de robustez de semillas/paráfrasis. Esas suites quedan sin probar. Mantén separados los informes rápidos; utiliza `full` para comparaciones oficiales y publicaciones. Ambos perfiles son estáticos: quick reduce la cobertura, no activa el modo adaptativo.

## Benchmark automatizado

El workflow `.github/workflows/local-model-benchmark.yml` ejecuta el protocolo completo contra los siete GGUF de la tabla anterior: SmolLM2 360M; Qwen2.5 0,5B y 3B; Llama 3.2 1B y 3B; Gemma 3 1B y 4B. Para cada modelo inicia `llama-server` en CPU, ejecuta el catálogo estático íntegro, escenarios multi-turno deterministas, pruebas emparejadas inglés/español, controles benignos y la matriz de robustez estratificada por baseline. Publica SQLite, JSON, Markdown, logs, hoja de revisión y procedencia como artefactos.

Puede iniciarse desde **Actions → Local model red-team benchmark → Run workflow**. El benchmark oficial utiliza `benchmark_profile=full` y registra `benchmark_mode=static`. Los cambios de catálogo/workflow no lanzan por sí solos el benchmark costoso; se despacha expresamente cuando está listo. Utiliza modelos públicos y no necesita secretos API.

El autoataque adaptativo queda fuera de la comparación oficial. El objetivo actuando también como atacante genera seguimientos dependientes de respuestas previas, por lo que los modelos pueden recibir trayectorias distintas; esto dificulta atribuir diferencias al modelo y añade coste de inferencia CPU. El modo adaptativo sigue disponible en la CLI para investigación exploratoria, pero sus resultados no se mezclan con los oficiales. Consulta la [metodología del benchmark oficial](../docs/official-benchmark-methodology.es.md). El rendimiento de los runners CPU y los timeouts pueden variar; una ejecución fallida se registra como fallida, nunca como resultado limpio de seguridad.


## Caché persistente de modelos

El workflow restaura cada uno de los siete GGUF desde su propia entrada de caché de GitHub Actions, valida los metadatos laterales y vuelve a calcular SHA-256 antes de la inferencia. La primera ejecución tras una ausencia de caché descarga el modelo; las siguientes lo reutilizan mientras GitHub conserve la entrada. La caché puede ser expulsada por las políticas de almacenamiento y retención, por lo que no equivale a tener los pesos instalados permanentemente en cada runner efímero. La preparación manual de caché se realiza mediante **Actions → Prepare local model cache** en `main`; descarga los tres modelos grandes añadidos —Qwen2.5 3B, Llama 3.2 3B y Gemma 3 4B—, resuelve sus revisiones y registra SHA-256. No ejecuta inferencias ni ataques.
