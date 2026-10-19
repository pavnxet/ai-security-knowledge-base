import subprocess,json,re,sys
t=subprocess.run([sys.executable,"bench/run_bench.py"],capture_output=True,text=True).stdout
d=json.loads(t[t.index("{"):t.rindex("}")+1])
h=d["heldout"]; lc=d["lab_coverage"]
print(f"cards={d['cards']} | all r@5={h['all']['recall@5']} | v1={h['curated_v1']['recall@5']} | v2={h['curated_v2']['recall@5']} | templ={h['templated']['recall@5']} | lab={lc['coverage_pct']}% | gate={lc['gate_recall_pct']}% | p50={h['all']['p50_ms']}ms")
