#!/usr/bin/env python3
"""Deterministic ingestion from cache/ (populated by fetch_sources.py at pinned commits).

Produces staging/*.jsonl with the same logic used to build the committed corpus.
staging/ is NOT committed; this script + sources_files.tsv + fetch_sources.py are the source of truth.
"""
import os, re, csv, io, json, glob, yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(ROOT, "cache")
STAGING = os.path.join(ROOT, "staging")
COMMITS = {}
for l in open(os.path.join(ROOT, "sources_files.tsv")):
    if l.strip():
        r, c, p = l.rstrip("\n").split("\t", 2)
        COMMITS[r] = c

def strip_fm(t):
    """Drop a leading YAML front-matter block (--- ... ---) before cleaning."""
    return re.sub(r"^\s*---\s*\n.*?\n---\s*\n", "", t or "", count=1, flags=re.S)

def cpath(repo, path): return os.path.join(CACHE, repo.replace("/", "__"), path)
def clean(t): return re.sub(r"\s+", " ", re.sub(r"[#*`>|]", " ", t or "")).strip()
def items_of(repo): return sorted(glob.glob(os.path.join(CACHE, repo.replace("/", "__"), "**", "*"), recursive=True))
def rel(repo, full): return os.path.relpath(full, os.path.join(CACHE, repo.replace("/", "__")))

def emit(name, items):
    os.makedirs(STAGING, exist_ok=True)
    with open(os.path.join(STAGING, name + ".jsonl"), "w") as f:
        for it in items: f.write(json.dumps(it, ensure_ascii=False) + "\n")
    return len(items)

def asvs():
    f = cpath("OWASP/ASVS", "5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv")
    rows = list(csv.DictReader(open(f)))
    return [{"source_repo":"OWASP/ASVS","commit":COMMITS["OWASP/ASVS"],
             "path":"5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv",
             "anchor":r["req_id"],"raw_text":clean(r["req_description"]),"official_id":f"ASVS:{r['req_id']}",
             "meta":{"chapter_id":r["chapter_id"],"chapter_name":r["chapter_name"],"section_id":r["section_id"],
                     "section_name":r["section_name"],"level":r["L"]}} for r in rows if r.get("req_id")]

def masvs():
    d = yaml.safe_load(open(cpath("OWASP/masvs","OWASP_MASVS.yaml")))
    out=[]
    for g in d.get("groups",[]):
        for c in g.get("controls",[]):
            st=c.get("statement") or c.get("description") or ""
            out.append({"source_repo":"OWASP/masvs","commit":COMMITS["OWASP/masvs"],"path":"OWASP_MASVS.yaml",
                        "anchor":c["id"],"raw_text":clean(st),"official_id":c["id"],
                        "meta":{"group":g["id"],"title":c.get("title","")}})
    return out

def wstg():
    d = json.load(open(cpath("OWASP/wstg","checklists/checklist.json")))
    items=[]
    for cat, body in d["categories"].items():
        for t in body["tests"]:
            objs = " ".join(clean(o) for o in t.get("objectives", []))
            items.append({"source_repo":"OWASP/wstg","commit":COMMITS["OWASP/wstg"],"path":"checklists/checklist.json",
                          "anchor":t["id"],"raw_text":clean(f"{t['name']}. {objs}"),"official_id":t["id"],
                          "meta":{"category":cat,"category_id":body["id"],"name":clean(t["name"]),
                                  "reference":t.get("reference"),"objectives":[clean(o) for o in t.get("objectives",[])]}})
    return items

def _risk(repo, path, official_id, anchor, meta):
    txt=open(cpath(repo,path),encoding="utf-8",errors="ignore").read()
    paras=[clean(p) for p in re.split(r"\n\s*\n", txt) if clean(p) and not p.strip().startswith("#")]
    desc=next((p for p in paras if len(p)>60), clean(txt)[:400])
    return {"source_repo":repo,"commit":COMMITS[repo],"path":path,"anchor":anchor,"raw_text":desc[:900],
            "official_id":official_id,"meta":meta}

def top10():
    out=[]
    for f in items_of("OWASP/Top10"):
        n=os.path.basename(f)
        if re.match(r"A\d+_2025-", n):
            aid=n.split("_")[0]
            out.append(_risk("OWASP/Top10", rel("OWASP/Top10",f), f"Top10:{aid}:2025", f"{aid}:2025",
                             {"rank":aid,"slug":n}))
    return sorted(out, key=lambda x:x["official_id"])

def api():
    out=[]
    for f in items_of("OWASP/API-Security"):
        n=os.path.basename(f)
        if n.startswith("0xa"):
            hx=re.match(r"0x([0-9a-f]+)-",n).group(1)
            num=10 if hx=="aa" else int(hx[1:])
            out.append(_risk("OWASP/API-Security", rel("OWASP/API-Security",f), f"API{num}:2023", f"API{num}:2023",
                             {"rank":num,"slug":n}))
    return sorted(out, key=lambda x:int(re.search(r"\d+",x["official_id"]).group()))

def llm():
    out=[]
    for f in items_of("OWASP/www-project-top-10-for-large-language-model-applications"):
        n=os.path.basename(f)
        m=re.match(r"(LLM\d+)_",n)
        if m and m.group(1)!="LLM00":
            lid=m.group(1)
            out.append(_risk("OWASP/www-project-top-10-for-large-language-model-applications",
                             rel("OWASP/www-project-top-10-for-large-language-model-applications",f),
                             f"{lid}:2025", f"{lid}:2025", {"rank":lid,"slug":n}))
    return sorted(out, key=lambda x:x["official_id"])

def cheatsheets():
    out=[]
    for f in items_of("OWASP/CheatSheetSeries"):
        if not f.endswith(".md"): continue
        name=os.path.basename(f)
        txt=open(f,encoding="utf-8",errors="ignore").read()
        n=0
        for part in re.split(r"\n(?=##\s)", txt):
            m=re.match(r"##\s+(.+)", part.strip())
            if not m: continue
            h=m.group(1).strip()
            body=clean(re.sub(r"```.*?```"," ",part,flags=re.S))
            if len(body)<40: continue
            out.append({"source_repo":"OWASP/CheatSheetSeries","commit":COMMITS["OWASP/CheatSheetSeries"],
                        "path":f"cheatsheets/{name}","anchor":h,"raw_text":body[:900],
                        "official_id":f"CS:{name[:-3]}#{h[:40]}","meta":{"sheet":name[:-3],"heading":h}})
            n+=1
        if n==0:
            body=clean(re.sub(r"```.*?```"," ",txt,flags=re.S))
            out.append({"source_repo":"OWASP/CheatSheetSeries","commit":COMMITS["OWASP/CheatSheetSeries"],
                        "path":f"cheatsheets/{name}","anchor":"(whole sheet)","raw_text":body[:900],
                        "official_id":f"CS:{name[:-3]}#overview","meta":{"sheet":name[:-3],"heading":"(whole sheet)"}})
    return out

def mastg():
    out=[]
    for f in items_of("OWASP/mastg"):
        n=os.path.basename(f)
        if not n.startswith("MASTG-TEST"): continue
        p=rel("OWASP/mastg",f)
        parts=p.split("/")
        plat=parts[1] if len(parts)>2 else ""; grp=parts[2] if len(parts)>2 else ""
        txt=open(f,encoding="utf-8",errors="ignore").read()
        tid=re.match(r"(MASTG-TEST-\d+)",n).group(1)
        paras=[clean(x) for x in re.split(r"\n\s*\n",txt) if clean(x) and not x.strip().startswith("#")]
        desc=next((x for x in paras if len(x)>50), clean(txt)[:300])
        out.append({"source_repo":"OWASP/mastg","commit":COMMITS["OWASP/mastg"],"path":p,"anchor":tid,
                    "raw_text":desc[:900],"official_id":tid,"meta":{"masvs":grp,"platform":plat,"test_id":tid}})
    return sorted(out, key=lambda x:(x["path"]))

def web3():
    out=[]
    for f in items_of("kadenzipfel/smart-contract-vulnerabilities"):
        if not f.endswith(".md"): continue
        n=os.path.basename(f)
        txt=open(f,encoding="utf-8",errors="ignore").read()
        title=next((l.strip("# ").strip() for l in txt.splitlines() if l.startswith("#")), n[:-3])
        out.append({"source_repo":"kadenzipfel/smart-contract-vulnerabilities",
                    "commit":COMMITS["kadenzipfel/smart-contract-vulnerabilities"],"path":rel("kadenzipfel/smart-contract-vulnerabilities",f),
                    "anchor":title,"raw_text":clean(txt)[:900],"official_id":f"SCV:{title[:40]}","meta":{"title":title}})
    for f in items_of("crytic/not-so-smart-contracts"):
        if not f.endswith(".md"): continue
        n=os.path.basename(f)
        txt=open(f,encoding="utf-8",errors="ignore").read()
        title=next((l.strip("# ").strip() for l in txt.splitlines() if l.startswith("#")), n[:-3])
        out.append({"source_repo":"crytic/not-so-smart-contracts",
                    "commit":COMMITS["crytic/not-so-smart-contracts"],"path":rel("crytic/not-so-smart-contracts",f),
                    "anchor":title,"raw_text":clean(txt)[:900],"official_id":f"NSSC:{title[:40]}","meta":{"title":title}})
    return out

def istg():
    out=[]
    for f in items_of("OWASP/owasp-istg"):
        if not f.endswith(".md"): continue
        n=os.path.basename(f); txt=open(f,encoding="utf-8",errors="ignore").read()
        title=next((l.strip("# ").strip() for l in txt.splitlines() if l.startswith("#")), n[:-3])
        out.append({"source_repo":"OWASP/owasp-istg","commit":COMMITS["OWASP/owasp-istg"],"path":rel("OWASP/owasp-istg",f),
                    "anchor":title,"raw_text":clean(txt)[:900],"official_id":f"ISTG:{title[:40]}","meta":{"title":title}})
    return out

def vibe():
    out=[]
    for f in items_of("raroque/vibe-security-skill"):
        if not f.endswith(".md") or "/references/" not in f: continue
        n=os.path.basename(f); txt=open(f,encoding="utf-8",errors="ignore").read()
        for part in re.split(r"\n(?=##\s)", txt):
            m=re.match(r"##\s+(.+)", part.strip())
            if not m: continue
            h=m.group(1).strip(); body=clean(part)
            if len(body)<40: continue
            out.append({"source_repo":"raroque/vibe-security-skill","commit":COMMITS["raroque/vibe-security-skill"],
                        "path":rel("raroque/vibe-security-skill",f),"anchor":h,"raw_text":body[:900],
                        "official_id":f"VIBE:{n[:-3]}#{h[:40]}","meta":{"heading":h,"sheet":n[:-3]}})
    return out

def tier2():
    out=[]
    def split(repo, path, prefix):
        txt=open(cpath(repo,path),encoding="utf-8",errors="ignore").read()
        res=[]
        for part in re.split(r"\n(?=#{2,3}\s)", txt):
            m=re.match(r"#{2,3}\s+(.+)", part.strip())
            if not m: continue
            h=m.group(1).strip(); body=clean(re.sub(r"```.*?```"," ",part,flags=re.S))
            if len(body)<40: continue
            res.append({"source_repo":repo,"commit":COMMITS[repo],"path":path,"anchor":h,"raw_text":body[:900],
                        "official_id":f"{prefix}:{h[:40]}","meta":{"heading":h}})
        return res
    out += split("shieldfy/API-Security-Checklist","README.md","API-CHK")
    for f in items_of("yesmayank/secure-coding-baseline"):
        if f.endswith(".md"): out += split("yesmayank/secure-coding-baseline", rel("yesmayank/secure-coding-baseline",f), "BASE")
    out += split("mgreiler/secure-code-review-checklist","README.md","SCR")
    return out

PARSERS = [("OWASP__ASVS",asvs),("OWASP__masvs",masvs),("OWASP__wstg",wstg),("OWASP__Top10",top10),
           ("OWASP__API-Security",api),("OWASP__www-project-top-10-for-large-language-model-applications",llm),
           ("OWASP__CheatSheetSeries",cheatsheets),("OWASP__mastg",mastg),
           ("kadenzipfel__smart-contract-vulnerabilities+OWASP",web3),
           ("OWASP__owasp-istg",istg),("raroque__vibe-security-skill",vibe),
           ("tier2",tier2)]

def _cwes_from_source(repo, path):
    import re as _re
    try:
        t = open(cpath(repo, path), encoding="utf-8", errors="ignore").read()
    except Exception:
        return []
    return sorted({f"CWE-{n}" for n in _re.findall(r"CWE-?(\d+)", t, _re.I)})

def main():
    total=0
    for name, fn in PARSERS:
        try:
            items = fn()
            for it in items:
                cw = _cwes_from_source(it["source_repo"], it["path"])
                if cw: it.setdefault("meta", {})["cwe"] = sorted(set(it["meta"].get("cwe") or []) | set(cw))
            n=emit(name if not name.startswith("kadenzipfel") else "web3", items)
            total+=n; print(f"  {name}: {n}")
        except Exception as e:
            print(f"  {name}: ERROR {str(e)[:80]}")
    print("staging items:", total)

if __name__ == "__main__": main()
