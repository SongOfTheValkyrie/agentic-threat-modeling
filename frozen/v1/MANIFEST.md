# V1 freeze

Frozen state of the benchmark **before** any ground-truth / matching changes.
Do not edit. V2 is developed separately; V1 stays as the reference so we can
show how much the benchmark definition itself moves the ranking.

- **Code/data commit:** `995ff61468cfa8f6171d62abe827ce600ee732cf` (code, ground truth, knowledge base and evaluator are
  identical in the tagged freeze commit, which only adds `frozen/`). Git tag: `v1-benchmark`.
- **Results snapshot:** `frozen/v1/results_snapshot.tar.gz`
  (sha256 `f1c4fc1bef5e9857`; contains `results/` incl. traces and archives,
  which are gitignored and therefore not covered by the tag)

## Evaluation configuration (V1)

- **Match key:** `(component_id or data_flow_id, STRIDE category)` — the
  description/root cause is **not** compared (`threat_key` in `evaluator.py`).
- **Metrics:** precision / recall / F1 over the set of keys; recall per
  difficulty class (difficulty is taken from the ground truth).
- **Difficulty rule used when tagging:** `easy` = exactly the keys the
  deterministic baseline finds from single attributes; the rest `medium`/`hard`.
- **Model:** Ollama `llama3.1:8b`, `temperature=0.0`.
- **Retrieval:** `KeywordRetriever`, weights applies_to 3.0 / keywords 2.0 /
  title 1.0 / text 0.5, k=4, 23-snippet knowledge base.
- **PEV:** `MAX_ADAPTIVE_CALLS=3`; ablation switches via env vars in `main.py`.
- **Dev set:** simple_web_api, webapp_with_auth, microservices_async,
  cloud_ingest_pipeline, multi_tenant_saas. **Holdout:** cicd_pipeline,
  mobile_banking (not yet evaluated).
- **Ground truth size:** 96 threats over 7 architectures.

## Known limitations of V1 (identified after the freeze, not fixed in V1)

1. Matching ignores root cause: a prediction with the right key but a different
   cause counts as a true positive.
2. Several ground-truth entries are hypothetical rather than evidenced by the
   architecture (e.g. simple_web_api), and some evidence/difficulty labels are
   inconsistent (e.g. `raw_bucket_tampering` assumes write access that is not
   configured; `ingest_api_denial_of_service` is `hard` although
   `rate_limiting_enabled: false` is stated directly).
3. The knowledge base and architectures were developed together, which may
   favour RAG.
4. **No stored run contains threat descriptions** — only keys
   (`matched_keys`, `proposed_keys`, `confirmed_keys`, ...). V1 runs therefore
   cannot be re-scored with cause-based matching.

## Checksums (first 16 hex chars of sha256)

| file | sha256 |
|---|---|
| `src/evaluation/evaluator.py` | `01f2940893ba482c` |
| `data/knowledge_base.json` | `69e6895650cee096` |
| `src/RAG/retriever.py` | `416b8792ce79494f` |
| `src/RAG/query_builder.py` | `74938f74ad3be68f` |
| `src/RAG/pipeline.py` | `88f72e251f3392fa` |
| `src/agent/structured.py` | `778bca40d521d0a7` |
| `src/agent/modeler.py` | `985948e84cb00870` |
| `benchmark/cloud_ingest_pipeline.ground_truth.json` | `65254b4f52767bd7` |
| `benchmark/cloud_ingest_pipeline.json` | `541b30977a0b1cde` |
| `benchmark/holdout/cicd_pipeline.ground_truth.json` | `e4468359de81509e` |
| `benchmark/holdout/cicd_pipeline.json` | `f0cfa34027abf834` |
| `benchmark/holdout/mobile_banking.ground_truth.json` | `d203dddc4994a836` |
| `benchmark/holdout/mobile_banking.json` | `450ef750323141e2` |
| `benchmark/microservices_async.ground_truth.json` | `83824e6f09695a86` |
| `benchmark/microservices_async.json` | `0f3aaaecd3b838de` |
| `benchmark/multi_tenant_saas.ground_truth.json` | `04e2508e6ef9e146` |
| `benchmark/multi_tenant_saas.json` | `74f16ea7b8812904` |
| `benchmark/simple_web_api.ground_truth.json` | `55c1465b17440c9d` |
| `benchmark/simple_web_api.json` | `d4371aec825d08a2` |
| `benchmark/webapp_with_auth.ground_truth.json` | `eef5ffcce6422b7f` |
| `benchmark/webapp_with_auth.json` | `442fa888fec1e2ed` |
