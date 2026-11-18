# Recursos de modelos locales y kit de benchmark

Modelos GGUF pequeños para pruebas reproducibles de inferencia local. Los pesos se descargan bajo demanda y no se guardan en el repositorio.

| ID | Familia / repositorio GGUF | Parámetros | Cuantización | Tamaño aprox. | Licencia |
| --- | --- | ---: | --- | ---: | --- |
| smollm2 | [SmolLM2](https://huggingface.co/tensorblock/SmolLM2-360M-Instruct-GGUF) | 360M | Q4_K_M | 271 MB | Apache-2.0 |
| qwen2_5 | [Qwen2.5](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF) | 0,5B | Q4_K_M | 491 MB | Apache-2.0 |
| llama3_2_1b | [Llama 3.2](https://huggingface.co/bartowski/Llama-3.2-1B-Instruct-GGUF) | 1B | Q4_K_M | 808 MB | Llama 3.2 Community License |
| gemma3_1b | [Gemma 3](https://huggingface.co/bartowski/google_gemma-3-1b-it-GGUF) | 1B | Q4_K_M | 806 MB | Gemma Terms |
| granite3_3_2b | [Granite 3.3](https://huggingface.co/bartowski/ibm-granite_granite-3.3-2b-instruct-GGUF) | 2B | Q4_K_M | 1,55 GB | Apache-2.0 |
| phi3_5_mini | [Phi-3.5 Mini](https://huggingface.co/bartowski/Phi-3.5-mini-instruct-GGUF) | 3,8B | Q4_K_M | 2,39 GB | MIT |
| ministral_3b | [Ministral 3B](https://huggingface.co/tensorblock/Ministral-3b-instruct-GGUF) | 3B | Q4_K_M | 1,86 GB | Apache-2.0 |

Los GGUF son cuantizaciones comunitarias. Cada entrada identifica el repositorio cuantizado y el modelo original. Llama y Gemma tienen condiciones propias: consulta las tarjetas y licencias upstream antes de redistribuir o usar comercialmente. SmolLM2 está orientado principalmente al inglés; Qwen2.5 es multilingüe. No extrapoles una puntuación de un idioma a otro.

## Descarga e integridad

Desde la raíz del repositorio:

```bash
python scripts/download_models.py --list
python scripts/download_models.py --model llama3_2_1b
python scripts/download_models.py --model gemma3_1b
python scripts/download_models.py --model granite3_3_2b
python scripts/download_models.py --model phi3_5_mini
python scripts/download_models.py --model ministral_3b
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

## Benchmark automatizado

El workflow `.github/workflows/local-model-benchmark.yml` ejecuta el catálogo integrado contra los siete GGUF. Para cada modelo inicia `llama-server` en CPU, genera un informe estático y otro adaptativo (autojuego de dos rondas) y publica SQLite, JSON, Markdown, logs y procedencia como artefactos.

Puede iniciarse desde **Actions → Local model red-team benchmark → Run workflow**. También se dispara cuando cambian en `main` el workflow, el descargador/catálogo o el escáner. Utiliza modelos públicos y no necesita secretos API.

En el modo adaptativo, el modelo evaluado también actúa como atacante. Es una prueba de estrés por autojuego reproducible, no una evaluación con un atacante independiente. El rendimiento de los runners CPU y los timeouts pueden variar; una ejecución fallida se registra como fallida, nunca como resultado limpio de seguridad.
