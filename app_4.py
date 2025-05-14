# app.py  ·  Value‑Chain Builder  (Streamlit + st_link_analysis)
# ==========================================================================
# • Build phases / segments / processes, connect processes
# • Drag nodes, click ⇩ Export JSON for fresh coordinates
# • Click a green “process” node → edit its details in a form
# • Save .vc  → upload Export‑JSON + password  (positions & edges kept)
# • Load .vc  → graph comes back exactly
# ==========================================================================

from __future__ import annotations
import json, os, secrets, base64, streamlit as st
from typing import Dict, Any, List
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from st_link_analysis import (
    st_link_analysis, NodeStyle, EdgeStyle, Event          # ← NEW: Event
)

st.set_page_config(layout="wide")

# ──────────────────────────────────────────────────────────────────────────
#  Fixed lookup tables
# ──────────────────────────────────────────────────────────────────────────
PROCESS_CATEGORIES = [
    "Transport","Storage","Use","Cleaning","Waste Handling","Packaging",
    "Administration","Inspection","Maintenance","Production","Sorting","Sterilization",
]
ICON_MAP = {
    "Transport":"directions_car","Storage":"storage","Use":"person",
    "Cleaning":"clean_hands","Waste Handling":"delete_sweep","Packaging":"inventory",
    "Administration":"description","Inspection":"visibility","Maintenance":"build",
    "Production":"factory","Sorting":"swap_horiz","Sterilization":"science",
}
DEFAULT_CATEGORY_COLORS = {
    "Transport":"#1f77b4","Storage":"#ff7f0e","Use":"#2ca02c","Cleaning":"#d62728",
    "Waste Handling":"#9467bd","Packaging":"#8c564b","Administration":"#e377c2",
    "Inspection":"#7f7f7f","Maintenance":"#bcbd22","Production":"#17becf",
    "Sorting":"#aec7e8","Sterilization":"#ffbb78",
}


# ──────────────────────────────────────────────────────────────────────────
#  Fixed edge catalogue  ← NEW
# ──────────────────────────────────────────────────────────────────────────
EDGE_TYPES = {                       # human → internal description
    "Material flow": {
        "cls": "mat_flow",
        "color": "#27ae60",
        "style": "solid",
        "both_arrows": False,
    },
    "Data transfer": {
        "cls": "data_transfer",
        "color": "#2980b9",
        "style": "dashed",
        "both_arrows": False,
    },
    "Data request (query)": {
        "cls": "data_request",
        "color": "#e67e22",
        "style": "dotted",
        "both_arrows": True,         # ← arrow heads on both ends
    },
}


import re
def _recompute_counters(g: dict[str, list[dict]]) -> dict[str, int]:
    """
    Look at every node / edge ID in the graph and find the maximum numeric
    suffix for phases, segments, processes, edges.  Return **next** numbers.
    """
    patt = {
        "phase"   : re.compile(r"^P(\d+)$"),
        "segment" : re.compile(r"^S(\d+)$"),
        "process" : re.compile(r"^proc_(\d+)$"),
        "edge"    : re.compile(r"^E(\d+)$"),
    }
    max_seen = {k: -1 for k in patt}          # -1 → nothing found yet

    for n in g.get("nodes", []):
        for kind, rx in patt.items():
            m = rx.match(n["data"]["id"])
            if m:
                max_seen[kind] = max(max_seen[kind], int(m.group(1)))

    for e in g.get("edges", []):
        m = patt["edge"].match(e["data"]["id"])
        if m:
            max_seen["edge"] = max(max_seen["edge"], int(m.group(1)))

    # we want the *next* free number
    return {k: v + 1 for k, v in max_seen.items()}



# ──────────────────────────────────────────────────────────────────────────
#  AES‑GCM helpers
# ──────────────────────────────────────────────────────────────────────────
PBKDF_ITERS, SALT_LEN, NONCE_LEN = 390_000, 16, 12
def _key(pw,salt): return PBKDF2HMAC(hashes.SHA256(),32,salt,PBKDF_ITERS).derive(pw.encode())
encrypt = lambda d,pw:(s:=os.urandom(SALT_LEN),n:=os.urandom(NONCE_LEN),
                       s+n+AESGCM(_key(pw,s)).encrypt(n,json.dumps(d).encode(),None))[2]
def decrypt(b:bytes,pw:str)->dict:
    s,n=b[:SALT_LEN],b[SALT_LEN:SALT_LEN+NONCE_LEN]; ct=b[SALT_LEN+NONCE_LEN:]
    return json.loads(AESGCM(_key(pw,s)).decrypt(n,ct,None).decode())

def as_graph(obj: Any)->Dict[str,List[dict]]:
    """Accept any Cytoscape export JSON shape → {'nodes':…,'edges':…}"""
    if isinstance(obj,dict) and "elements" in obj:
        elm = obj["elements"]
        if isinstance(elm,dict):  # {"nodes":[…],"edges":[…]}
            return {"nodes":elm.get("nodes",[]),"edges":elm.get("edges",[])}
        obj = elm                 # fall‑through to list handler
    if isinstance(obj,list):
        nodes=[e for e in obj if "position" in e]
        edges=[e for e in obj if "position" not in e]
        return {"nodes":nodes,"edges":edges}
    raise ValueError("Unrecognised export‑JSON")

# ──────────────────────────────────────────────────────────────────────────
#  Session‑state containers
# ──────────────────────────────────────────────────────────────────────────
if "graph" not in st.session_state:
    st.session_state.graph  = {"nodes":[], "edges":[]}
    st.session_state.count = _recompute_counters(st.session_state.graph)
    st.session_state.cy_key = 0           # forces component remounts
    st.session_state.selected_proc = None # last‑clicked process ID

graph:Dict[str,Any]=st.session_state.graph
C = st.session_state.count
_next = lambda k:(C.update({k:C[k]+1}) or
                 {"phase":f"P{C['phase']}",
                  "segment":f"S{C['segment']}",
                  "process":f"proc_{C['process']}",
                  "edge":f"E{C['edge']}"}[k])

def _add_node(kind:str,lbl:str,parent:str|None=None,
              category:str|None=None,color:str|None=None):
    classes = kind
    if kind=="process" and category:
        classes=f"{kind} {category.lower().replace(' ','_')}"
    n={"data":{"id":_next(kind),"label":lbl}, "classes":classes}
    if parent: n["data"]["parent"]=parent
    if kind=="process" and category: n["data"]["category"]=category
    if color is not None: n["data"]["color"]=color
    graph["nodes"].append(n)

def _add_edge(src: str, tgt: str, edge_kind: str):
    """
    Insert an edge with a known type (Material flow, Data transfer, …).

    `edge_kind` **must** be one of the human-readable keys of EDGE_TYPES.
    """
    if edge_kind not in EDGE_TYPES:
        raise ValueError(f"Unknown edge type: {edge_kind}")

    e_def = EDGE_TYPES[edge_kind]

    graph["edges"].append({
        "data": {
            "id": _next("edge"),
            "source": src,
            "target": tgt,
            "label": edge_kind,          # shown when you hover
            "edge_type": e_def["cls"],   # nice to have in exports
        },
        "classes": e_def["cls"],         # drives Cytoscape style
    })


# ──────────────────────────────────────────────────────────────────────────
#  Sidebar – builders & I/O
# ──────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("🎛️ Value‑Chain Builder")

    # ➕ Add Phase
    with st.expander("➕ Add Phase", expanded=False):
        phase_name  = st.text_input("Name", key="phase_name")
        phase_color = st.color_picker("Border color", "#95a5a6", key="phase_color")
        if st.button("Add Phase", disabled=not phase_name, key="add_phase_btn"):
            _add_node("phase", phase_name, color=phase_color)
            st.rerun()

    # ➕ Add Segment
    with st.expander("➕ Add Segment", expanded=False):
        phases = [n for n in graph["nodes"] if n["classes"]=="phase"]
        if not phases: st.info("Create a phase first.")
        else:
            seg_name = st.text_input("Name", key="seg_name")
            phase_map= {p["data"]["label"]:p for p in phases}
            parent_lbl= st.selectbox("Parent phase", phase_map, key="seg_parent")
            color     = phase_map[parent_lbl]["data"].get("color","#95a5a6")
            if st.button("Add Segment", disabled=not seg_name, key="add_seg_btn"):
                _add_node("segment", seg_name,
                          parent=phase_map[parent_lbl]["data"]["id"],
                          color=color)
                st.rerun()

    # ➕ Add Process
    with st.expander("➕ Add Process", expanded=False):
        segs=[n for n in graph["nodes"] if n["classes"]=="segment"]
        if not segs: st.info("Create a segment first.")
        else:
            proc_name = st.text_input("Name", key="proc_name")
            seg_opts  = {s["data"]["label"]:s["data"]["id"] for s in segs}
            parent_seg= st.selectbox("Parent segment", seg_opts, key="proc_parent")
            proc_cat  = st.selectbox("Category", PROCESS_CATEGORIES, key="proc_cat")
            if st.button("Add Process", disabled=not proc_name, key="add_proc_btn"):
                _add_node("process", proc_name, parent=seg_opts[parent_seg],
                          category=proc_cat)
                st.rerun()

    # 🔗 Connect
    with st.expander("🔗 Connect Processes", False):
        procs = [n for n in graph["nodes"] if "process" in n["classes"]]
        if len(procs) < 2:
            st.info("Need at least two processes.")
        else:
            opts = {p["data"]["label"]: p["data"]["id"] for p in procs}
            src = st.selectbox("Source", opts, key="edge_src")
            tgt = st.selectbox("Target", opts, key="edge_tgt")

            edge_kind = st.selectbox(
                "Type of connection",
                list(EDGE_TYPES.keys()),
                key="edge_kind"
            )

            if st.button("Add Connection",
                        key="add_edge_btn",
                        disabled=src == tgt):
                _add_edge(opts[src], opts[tgt], edge_kind)
                st.rerun()


    st.markdown("---")

    # 💾 Save .vc
    with st.expander("💾 Save encrypted .vc"):
        up = st.file_uploader("Upload Export‑JSON", type="json", key="json_up")
        pw = st.text_input("Password", type="password", key="pw_save")
        if up and pw:
            try:
                export=as_graph(json.load(up))
                id2={n["data"]["id"]:n for n in graph["nodes"]}
                for elm in export["nodes"]:
                    pos=elm.get("position"); nid=elm["data"]["id"]
                    if pos and nid in id2: id2[nid]["position"]=pos
                blob=encrypt(graph,pw)
                st.download_button("⬇ Download value_chain.vc",blob,"value_chain.vc",
                                   "application/octet-stream",use_container_width=True)
            except Exception as e: st.error(f"Save failed: {e}")

    # 📂 Load .vc
    with st.expander("📂 Load .vc"):
        up = st.file_uploader("Choose file", type="vc", key="vc_up")
        pw = st.text_input("Password", type="password", key="pw_load")
        if st.button("Load", disabled=not (up and pw), key="load_btn"):
            try:
                st.session_state.graph = decrypt(up.read(), pw)

                # NEW – resynchronise counters
                st.session_state.count = _recompute_counters(st.session_state.graph)

                st.session_state.cy_key += 1
                st.session_state.selected_proc = None
                st.rerun()
            except Exception as e:
                st.error(f"Decrypt failed: {e}")


    # Logo
    # if os.path.exists("imgs/logo.png"):
    #     b64=base64.b64encode(open("imgs/logo.png","rb").read()).decode()
    #     st.markdown("""
    #     <style>
    #       #sidebar-logo{position:fixed;bottom:20px;left:130px;
    #                     transform:translateX(-50%);width:200px;}
    #       [data-testid="stSidebar"] > div:first-child{padding-bottom:80px;}
    #     </style>
    #     <img id="sidebar-logo" src="data:image/png;base64,%s"/>
    #     """%b64, unsafe_allow_html=True)

# ──────────────────────────────────────────────────────────────────────────
#  Cytoscape styles
# ──────────────────────────────────────────────────────────────────────────
class RawStyle:                               # helper wrapper
    def __init__(self,selector:str,style:dict): self.selector,self.style=selector,style
    def dump(self): return {"selector":self.selector,"style":self.style}

phase_style=RawStyle(".phase",{
    "shape":"round-rectangle","background-opacity":0,"border-width":"2px",
    "border-color":"data(color)","label":"data(label)","text-valign":"top",
    "font-weight":"bold","padding":"8px",
})
segment_style=RawStyle(".segment",{
    "shape":"round-rectangle","background-opacity":0,"border-width":"2px",
    "border-style":"dashed","border-color":"data(color)","label":"data(label)",
    "text-valign":"top","font-weight":"bold","padding":"8px",
})

category_styles=[]
for cat in PROCESS_CATEGORIES:
    cls=cat.lower().replace(" ","_")
    icon=f"url(./icons/{ICON_MAP[cat].lower()}.svg)"
    category_styles.append(RawStyle(f".process.{cls}",{
        "background-color":DEFAULT_CATEGORY_COLORS[cat],"background-image":icon,
        "background-fit":"none","background-clip":"node",
        "background-width":"60%","background-height":"60%","background-position":"center",
        "label":"data(label)","text-valign":"bottom","text-halign":"center",
    }))

node_styles=[phase_style,segment_style]+category_styles
edge_styles = []

for human_name, cfg in EDGE_TYPES.items():
    cls   = f".{cfg['cls']}"
    color = cfg["color"]

    style_dict = {
        "line-color": color,
        "width": 2 if cfg["cls"] == "mat_flow" else 2,
        "line-style": cfg["style"],
        # label on hover
        "label": "data(label)",
        "font-size": "4px",
        "text-background-color": color,
        "text-background-opacity": 1,
        "text-background-padding": "1px",
    }

    # arrow heads ---------------------------------------------------
    if cfg["both_arrows"]:
        style_dict.update({
            "target-arrow-shape": "triangle",
            "source-arrow-shape": "triangle",
            "target-arrow-color": color,
            "source-arrow-color": color,
        })
    else:
        style_dict.update({
            "target-arrow-shape": "triangle",
            "target-arrow-color": color,
            "source-arrow-shape": "none",
        })

    edge_styles.append(RawStyle(cls, style_dict))


# CSS hack – scale 50 %
st.markdown("""
<style>
iframe[title="st_link_analysis"]{
  width:200% !important; min-height:600px !important;
  transform:scale(0.9) !important; transform-origin:top left !important;
}
</style>""", unsafe_allow_html=True)



# ──────────────────────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────────────────────
def _node_summary(node_id: str, g: dict) -> dict:
    """Return {id, label, category} for a node id (never crashes)."""
    for n in g["nodes"]:
        if n["data"]["id"] == node_id:
            d = n["data"]
            return {"id": node_id,
                    "label": d.get("label"),
                    "category": d.get("category")}
    return {"id": node_id, "label": None, "category": None}


def slim_payload(pl, g: dict) -> dict:
    """
    Turn ANY payload coming from st_link_analysis into a friendly
    structure that contains only id / label / category.
    Handles both old (≤0.4) and new (≥0.5) schemas.
    """
    if pl is None:
        return {}

    # ─── list of elements (drag / first load) ───────────────────────
    if isinstance(pl, list):
        return {"elements": [_node_summary(el["data"]["id"], g) for el in pl]}

    # ─── dict: custom event or node-action ──────────────────────────
    if isinstance(pl, dict):
        nice = {"action": pl.get("action") or pl.get("name")}

        # new schema → id sits at data.target_id
        tgt_id = pl.get("data", {}).get("target_id")
        # old schema fallback → data.id
        tgt_id = tgt_id or pl.get("data", {}).get("id")

        if tgt_id:
            nice["clicked"] = _node_summary(tgt_id, g)

        # new versions may include selected list under `data.selected_ids`
        sel = pl.get("data", {}).get("selected_ids") \
              or pl.get("selected_ids") \
              or []
        nice["selected"] = [_node_summary(i, g) for i in sel]

        return nice

    # unknown type
    return {}



import numpy as np

import numpy as np

def _parse_amounts(entries: list[str]) -> np.ndarray:
    """Given ["Fe: 12 kg", "O2: 3.5 mol"], return array([12.0, 3.5])."""
    vals = []
    for e in entries:
        # split at “:”, take the part after, then split on space and parse float
        try:
            qty = e.split(":", 1)[1].strip().split()[0]
            vals.append(float(qty))
        except Exception:
            pass
    return np.array(vals, dtype=float)

def calculate_detail_score(io_lists: dict[str, list[str]]) -> float:
    """
    io_lists keys: "x","y","P","f","w", each a list of "Name: amount unit" strings.
    Computes D1–D4 and returns their unweighted mean.
    """
    x = _parse_amounts(io_lists.get("x", []))
    y = _parse_amounts(io_lists.get("y", []))
    f = _parse_amounts(io_lists.get("f", []))
    w = _parse_amounts(io_lists.get("w", []))
    # D1: mass/energy balance
    XY = np.concatenate([x, y]) if x.size or y.size else np.array([])
    FW = np.concatenate([f, w]) if f.size or w.size else np.array([])
    if XY.size == 0:
        D1 = 1.0
    else:
        D1 = 1 - (np.linalg.norm(XY - FW) / np.linalg.norm(XY))
    # D2: variation in outputs
    D2 = 1.0
    if f.size and np.mean(f) != 0:
        D2 = 1 - (np.std(f) / np.mean(f))
    # D3: placeholder (e.g. R² later)
    D3 = 0.0
    # D4: completeness of P (treat missing “:” as missing)
    P = io_lists.get("P", [])
    total = len(P)
    missing = sum(1 for p in P if ":" not in p or not p.split(":",1)[1].strip())
    D4 = 1 - (missing / total) if total else 1.0
    return float(np.mean([D1, D2, D3, D4]))




CLICK_EVENT = Event("proc_click", "tap", ".process")

with st.container(border=True):
    # ──────────── render component ────────────────────────────────
    payload = st_link_analysis(
        graph,
        node_styles=node_styles,
        edge_styles=edge_styles,
        events=[CLICK_EVENT],
        layout={"name": "preset"},
        height=600,
        node_actions=["remove"],
        key=f"cy_{st.session_state.cy_key}",
    )

    # st.markdown("#### Raw returned value")
    # st.json(payload or {}, expanded=False)

    # ──────────── clicked-node handling ───────────────────────────
    if (
        isinstance(payload, dict)
        and payload.get("action") == "proc_click"
        and isinstance(payload.get("data"), dict)
    ):
        clicked_id = payload["data"].get("target_id") or payload["data"].get("id")

        node_map = {n["data"]["id"]: n for n in graph["nodes"]}
        proc = node_map.get(clicked_id)

        if proc and "process" in proc["classes"]:

            # ========== 1) DETAILS  (rename / recategorise / delete) =====
            with st.expander(f"📝 Edit “{proc['data']['label']}”", expanded=False):
                cur_cat = proc["data"].get("category", PROCESS_CATEGORIES[0])

                with st.form(f"edit_{clicked_id}", border=True):
                    new_label = st.text_input(
                        "Name", value=proc["data"]["label"],
                        key=f"edit_lbl_{clicked_id}",
                    )
                    new_cat = st.selectbox(
                        "Category",
                        PROCESS_CATEGORIES,
                        index=PROCESS_CATEGORIES.index(cur_cat),
                        key=f"edit_cat_{clicked_id}",
                    )
                    if st.form_submit_button("✅ Save"):
                        proc["data"]["label"] = new_label
                        proc["data"]["category"] = new_cat
                        proc["classes"] = f"process {new_cat.lower().replace(' ','_')}"
                        proc["data"]["color"] = DEFAULT_CATEGORY_COLORS[new_cat]
                        st.success("Saved – refreshing …", icon="💾")
                        st.rerun()
                delete_clicked = st.button(
                    "🗑️  Delete this process",
                    type="secondary",
                    key=f"del_btn_{clicked_id}",
                )

                if delete_clicked:
                    # Pick the decorator that exists on this Streamlit version
                    dlg = getattr(st, "dialog", None) or st.experimental_dialog

                    @dlg(f"Confirm delete “{proc['data']['label']}”")
                    def _confirm_delete():
                        st.warning(
                            "This will remove the node **and** all its connections.",
                            icon="⚠️",
                        )

                        col_ok, col_cancel = st.columns(2)
                        if col_ok.button("Yes, delete", use_container_width=True):
                            # -- drop the node -----------------------------------------
                            graph["nodes"] = [
                                n for n in graph["nodes"]
                                if n["data"]["id"] != clicked_id
                            ]
                            graph["edges"] = [
                                e for e in graph["edges"]
                                if clicked_id not in (e["data"]["source"], e["data"]["target"])
                            ]
                            st.session_state.selected_proc = None
                            st.success("Deleted. Refreshing …")
                            st.rerun()

                        if col_cancel.button("Cancel", use_container_width=True):
                            st.rerun()          # just close the dialog

                    _confirm_delete()           # ← STEP ❷ – show the modal


            # ===== 2) NEW  I/O + PARAMS  ======================================
            # ===== 2) NEW  I/O + PARAMS  ======================================
            with st.expander("⚙️ Inputs / Outputs (x, y, P, w, f(x))", expanded=False):
                d = proc["data"]
                prefix = f"{clicked_id}_"
                placeholder_map = {
                                    "x": "e.g. PP: 12 kg",
                                    "y": "e.g. Electricity: 5 kWh",
                                    "P": "e.g. Temperature: 200 °C",
                                    "w": "e.g. PP: 1 kg",
                                }
                
                # initialize per-node lists (only once)
                for param in ["x","y","P","w"]:
                    ss_key = prefix + param
                    if ss_key not in st.session_state:
                        existing = d.get(param, "")
                        st.session_state[ss_key] = [
                            e.strip() for e in existing.split(",") if e.strip()
                        ]

                # --- Single caption in 2nd column above all inputs ---
                cap_col0, cap_col1, cap_col2 = st.columns([3, 5, 1])
                cap_col1.caption("Format: Name: amount unit")

                # one-line editors for each param
                for param, label in [
                    ("x","Input material (x)"),
                    ("y","Resources (y)"),
                    ("P","Process params (P)"),
                    ("w","Waste / rejects (w)")
                ]:
                    ss_key    = prefix + param
                    entry_key = f"{prefix}{param}_entry"
                    add_key   = f"{prefix}add_{param}"

                    col_label, col_input, col_button = st.columns([3,5,1])
                    col_label.markdown(f"**{label}**")
                    # this input no longer reserves a label-row
                    entry = col_input.text_input(
                        "", 
                        key=entry_key, 
                        label_visibility="collapsed",
                        placeholder=placeholder_map.get(param, "e.g. Name: amount unit")
                    )
                    if col_button.button("➕", key=add_key) and entry:
                        st.session_state[ss_key].append(entry)
                        st.rerun()


                    # list existing entries
                    for i, item in enumerate(st.session_state[ss_key]):
                        c1, c2 = st.columns([8,1])
                        c1.markdown(f"- {item}")
                        if c2.button("❌", key=f"{prefix}rem_{param}_{i}"):
                            st.session_state[ss_key].pop(i)
                            st.rerun()

                # f(x) stays a single field
                fx = st.text_input(
                    "f(x) – Output as function of x",
                    d.get("fx", ""), key=f"{prefix}fx"
                )

                # Save all I/O back into the node and recompute D
                if st.button("✅ Save I/O", key=f"{prefix}save_io"):
                    for param in ["x","y","P","w"]:
                        ss_key = prefix + param
                        d[param] = ",".join(st.session_state[ss_key])
                    d["fx"] = fx

                    d["D"] = calculate_detail_score({
                        param: d[param] for param in ["x","y","P","w", "fx"]
                    })

                    st.success("I/O updated – refreshing …", icon="💾")
                    st.rerun()


            # ========== 2) CONNECTION-CREATOR ============================
            other_procs = [
                (n["data"]["label"], n["data"]["id"])
                for n in graph["nodes"]
                if "process" in n["classes"] and n["data"]["id"] != clicked_id
            ]

            if other_procs:
                with st.expander("🔗 Create connection", expanded=False):
                    tgt_lbl = st.selectbox(
                        "Target process",
                        [lbl for lbl, _ in other_procs],
                        key=f"conn_tgt_{clicked_id}",
                    )
                    tgt_id = dict(other_procs)[tgt_lbl]

                    edge_kind = st.selectbox(
                    "Type of connection",
                    list(EDGE_TYPES.keys()),
                    key=f"conn_kind_{clicked_id}",
                )

                    if st.button(
                        "✅ Create connection",
                        key=f"mk_edge_{clicked_id}_{tgt_id}",
                    ):
                        _add_edge(clicked_id, tgt_id, edge_kind)     # ← pass the chosen type
                        st.success(f"Edge {clicked_id} → {tgt_id} created")
                        st.rerun()
            else:
                st.info("No other processes to connect to.")



