"""The multi-page web application shell (dashboard / scan / history / settings).

A single self-contained HTML document with hash-based routing that talks to the
JSON API. The detailed interactive report is rendered by report.py and opened per
scan from History/Dashboard. One inline script, allowed via a per-response nonce.
"""
from __future__ import annotations


def render_spa(nonce: str) -> str:
    return _SPA.replace("__NONCE__", nonce)


_SPA = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PostureHound</title><style>
:root{--bg:#0A0C12;--surface:#11151F;--raised:#171C29;--border:#242C3D;--border2:#323B50;
--tx:#EAEDF4;--tx2:#9BA5BC;--tx3:#5C667E;--accent:#D98A4B;--accent2:#7a5430;
--crit:#F25C70;--high:#FF914C;--med:#E8C257;--low:#5BB3E0;--ok:#56C08A;
--mono:ui-monospace,Menlo,Consolas,monospace;--sans:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,system-ui,sans-serif}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(1100px 600px at 80% -12%,rgba(217,138,75,.10),transparent),var(--bg);
color:var(--tx);font-family:var(--sans);min-height:100vh}
a{color:var(--accent);text-decoration:none}
header{display:flex;align-items:center;gap:14px;padding:16px 28px;border-bottom:1px solid var(--border);position:sticky;top:0;
background:rgba(10,12,18,.86);backdrop-filter:blur(8px);z-index:5}
.mark svg{display:block;flex:none}
.bn{font-weight:650}.bs{font-size:10.5px;color:var(--tx3);letter-spacing:.09em;text-transform:uppercase}
nav{display:flex;gap:4px;margin-left:24px}
nav a{padding:8px 14px;border-radius:9px;color:var(--tx2);font-size:13.5px;font-weight:550}
nav a.on{background:var(--raised);color:var(--tx)}
nav a:hover{color:var(--tx)}
.keypill{margin-left:auto;font-size:11px;color:var(--tx3);font-family:var(--mono);border:1px solid var(--border);border-radius:999px;padding:4px 11px}
.keypill.on{color:var(--ok);border-color:var(--accent2)}
.logout{margin-left:10px;font-size:11px;color:var(--tx3);font-family:var(--mono);background:none;border:1px solid var(--border);border-radius:999px;padding:4px 11px;cursor:pointer}
.logout:hover{color:var(--tx);border-color:var(--accent2)}
.pwbanner{background:#3a2a08;color:#f3c778;border-bottom:1px solid #5c4310;padding:8px 24px;font-size:12.5px;text-align:center}
.pwbanner a{color:#ffd98a;font-weight:600}
body.locked nav,body.locked .keypill,body.locked .logout{display:none}
.loginwrap{max-width:380px;margin:8vh auto 0;padding:0 20px}
.loginbox{padding:26px 26px 22px}
.loginbox .fl{display:block;margin:0 0 12px;font-size:12px;color:var(--tx2)}
.loginbox .fl input{display:block;width:100%;margin-top:5px;padding:9px 11px;background:var(--raised);border:1px solid var(--border);border-radius:8px;color:var(--tx);font-size:14px;box-sizing:border-box}
.loginerr{color:var(--crit,#E5484D);font-size:12.5px;min-height:16px;margin:2px 0 4px}
main{max-width:1080px;margin:0 auto;padding:30px 24px 60px}
h1{font-size:21px;margin:0 0 4px;letter-spacing:-.01em}.sub{color:var(--tx2);margin:0 0 22px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:22px;margin-bottom:18px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}
.tile{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 18px}
.tile .n{font-size:26px;font-weight:700}.tile .l{font-size:12px;color:var(--tx3);margin-top:2px}
.ring{--p:0;width:104px;height:104px;border-radius:50%;display:grid;place-items:center;flex:0 0 auto;
background:conic-gradient(var(--accent) calc(var(--p)*1%),var(--border) 0)}
.ring .inner{width:84px;height:84px;border-radius:50%;background:var(--surface);display:grid;place-items:center;text-align:center}
.ring .g{font-size:30px;font-weight:800;line-height:1}.ring .s{font-size:11px;color:var(--tx3)}
.hero{display:flex;gap:22px;align-items:center}
.hero .pt{font-size:13px;color:var(--tx2);line-height:1.5}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{text-align:left;color:var(--tx3);font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.05em;padding:8px 10px;border-bottom:1px solid var(--border)}
td{padding:11px 10px;border-bottom:1px solid var(--border)}
tr:hover td{background:var(--raised)}
.badge{display:inline-block;min-width:26px;text-align:center;font-weight:700;border-radius:6px;padding:2px 8px;font-size:12px}
.gA{background:rgba(86,192,138,.16);color:var(--ok)}.gB{background:rgba(91,179,224,.16);color:var(--low)}
.gC{background:rgba(232,194,87,.16);color:var(--med)}.gD{background:rgba(255,145,76,.16);color:var(--high)}
.gF{background:rgba(242,92,112,.16);color:var(--crit)}
button,.btn{background:var(--accent);border:0;color:#1a0f06;font-weight:700;padding:11px 18px;border-radius:10px;cursor:pointer;font-size:13.5px;font-family:var(--sans)}
button:hover{filter:brightness(1.07)}button:disabled{opacity:.5;cursor:default}
.ghost{background:transparent;border:1px solid var(--border2);color:var(--tx2)}
.danger{background:transparent;border:1px solid rgba(242,92,112,.4);color:var(--crit);padding:6px 12px;font-size:12.5px}
.rowacts{display:inline-flex;align-items:center;gap:2px;justify-content:flex-end}
.rowacts .sep{width:1px;height:16px;background:var(--border2);margin:0 5px;flex-shrink:0}
a.rowlink{color:var(--tx3);font-size:12px;font-weight:500;padding:5px 7px;border-radius:7px;text-decoration:none;white-space:nowrap}
a.rowlink:hover{color:var(--tx);background:var(--raised)}
.rowdel{background:transparent;border:0;color:var(--tx3);padding:5px 8px;font-size:14px;line-height:1;border-radius:7px;font-weight:400}
.rowdel:hover{background:rgba(242,92,112,.14);color:var(--crit);filter:none}
.tablewrap{overflow-x:auto}
input[type=file]{color:var(--tx2);width:100%}
input[type=password],input[type=text],input[type=number],select{width:100%;background:var(--bg);border:1px solid var(--border2);border-radius:9px;
padding:10px 12px;color:var(--tx);font-family:var(--mono);font-size:13px}
label.fld{display:block;font-size:13px;font-weight:600;margin:16px 0 6px}
.hint{color:var(--tx3);font-size:12px;margin-top:6px;line-height:1.5}
.drop{border:1.5px dashed var(--border2);border-radius:12px;padding:24px;text-align:center;background:var(--raised)}
.row{display:flex;align-items:center;gap:10px}
.chk{width:16px;height:16px;accent-color:var(--accent)}
.muted{color:var(--tx3)}.small{font-size:12px}
.banner{border:1px solid var(--high);background:rgba(255,145,76,.08);border-radius:10px;padding:12px 14px;margin-bottom:16px;font-size:13px}
.spin{display:inline-block;width:14px;height:14px;border:2px solid var(--border2);border-top-color:var(--accent);border-radius:50%;animation:sp .7s linear infinite;vertical-align:-2px}
@keyframes sp{to{transform:rotate(360deg)}}
.empty{text-align:center;color:var(--tx3);padding:40px 0}
.evalpipeline{display:flex;align-items:center;gap:10px;flex-wrap:wrap;background:var(--raised);border:1px solid var(--border);border-radius:10px;padding:12px 14px}
.evalpipeline .steplabel{font-size:13px;font-weight:700;display:flex;flex-direction:column}
.evalpipeline .stepsub{font-size:10.5px;font-weight:500;color:var(--tx3);text-transform:uppercase;letter-spacing:.04em}
.evalpipeline .stepcount{font-size:11.5px;color:var(--accent);font-family:var(--mono);background:rgba(217,138,75,.12);padding:3px 9px;border-radius:999px}
.evalpipeline .arrow{color:var(--tx3);font-size:16px}
.evalfinding{border:1px solid var(--border);border-radius:10px;padding:12px 14px;margin-bottom:10px;background:var(--bg)}
.evalfinding .efhead{display:flex;align-items:center;gap:8px;font-size:13.5px}
.evalfinding .sevdot{width:8px;height:8px;border-radius:50%;flex:0 0 auto}
.srctag{display:inline-block;font-size:10.5px;padding:2px 8px;border-radius:999px;font-weight:600;white-space:nowrap}
.srctag.ai{background:rgba(217,138,75,.16);color:var(--accent)}
.srctag.det{background:rgba(91,179,224,.14);color:var(--low)}
.dropicon{font-size:22px;color:var(--tx3);margin-bottom:6px}
.drop.over{border-color:var(--accent);background:rgba(217,138,75,.06)}
.filelabel{color:var(--accent);cursor:pointer;text-decoration:underline}
.filelist{margin-top:10px}
.fileitem{display:flex;align-items:center;gap:10px;padding:8px 12px;border:1px solid var(--border);border-radius:8px;margin-bottom:6px;font-size:13px;background:var(--raised)}
.fileitem .fn{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fileitem .fs{color:var(--tx3);font-size:11.5px;font-family:var(--mono)}
.fileitem .rmfile{background:transparent;border:0;color:var(--tx3);font-size:16px;cursor:pointer;padding:0 4px}
.fileitem .rmfile:hover{color:var(--crit)}
.livelog{margin-top:16px;border:1px solid var(--border);border-radius:10px;overflow:hidden}
.livelogtitle{background:var(--raised);padding:8px 14px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--tx3);border-bottom:1px solid var(--border)}
.logbody{max-height:260px;overflow-y:auto;padding:10px 14px;background:#05070C;font-family:var(--mono);font-size:12px}
.logrow{display:flex;gap:10px;padding:3px 0;line-height:1.5;animation:login .15s ease-out}
@keyframes login{from{opacity:0;transform:translateY(-2px)}to{opacity:1;transform:none}}
.logt{color:var(--tx3);flex:0 0 auto}
.logm{color:var(--tx2)}
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.toolbar{display:flex;gap:10px;align-items:center;margin-bottom:14px;flex-wrap:wrap}
.search{flex:1;min-width:180px;background:var(--bg);border:1px solid var(--border2);border-radius:9px;padding:9px 12px;color:var(--tx);font-size:13px;font-family:var(--sans);outline:none}
.search:focus{border-color:var(--accent)}.search::placeholder{color:var(--tx3)}
.hsort{background:var(--bg);border:1px solid var(--border2);border-radius:9px;padding:9px 11px;color:var(--tx);font-size:13px;outline:none}
.rbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
.rbar select{background:var(--bg);border:1px solid var(--border2);border-radius:9px;padding:8px 10px;color:var(--tx);font-size:12.5px;outline:none}
.rmeta{color:var(--tx3);font-size:12px;margin-bottom:8px}
.rtbl{width:100%;border-collapse:collapse;font-size:13px}
.rtbl th{text-align:left;color:var(--tx3);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em;padding:7px 8px;border-bottom:1px solid var(--border)}
.rtbl td{padding:8px;border-bottom:1px solid var(--border);vertical-align:top}
.rrow{cursor:pointer}.rrow:hover{background:var(--raised)}
.sevtag{display:inline-block;color:#0b0d14;font-weight:700;font-size:10.5px;padding:1px 7px;border-radius:5px}
.fwpill{display:inline-block;font-size:10px;font-weight:600;padding:1px 7px;border-radius:999px;margin:1px 3px 1px 0;border:1px solid var(--border);color:var(--tx2)}
.fwpill.cis{background:rgba(86,192,138,.14);color:#7fce9f;border-color:rgba(86,192,138,.35)}
.fwpill.mit{background:rgba(122,137,194,.14);color:#9aa8d6;border-color:rgba(122,137,194,.3)}
.fwpill.atrm{background:rgba(217,138,75,.14);color:#e0a366;border-color:rgba(217,138,75,.3)}
.bpdot{color:#7fce9f}
.rst{font-size:10.5px;font-weight:700;padding:1px 8px;border-radius:999px}
.rst-fired{background:rgba(242,92,112,.16);color:#f0a6aa;border:1px solid rgba(242,92,112,.35)}
.rst-silent{background:rgba(120,130,150,.14);color:var(--tx3);border:1px solid var(--border)}
.rst-na{background:rgba(232,194,87,.14);color:#e8c257;border:1px solid rgba(232,194,87,.3)}
.rdet{padding:6px 2px 4px;max-width:820px}
.rdet .rk{color:var(--tx3);font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;margin:12px 0 4px;font-weight:600}
.rdet p{margin:0;line-height:1.55;font-size:13px}
.hsort:focus{border-color:var(--accent)}
.sfinding{border:1px solid var(--border);border-radius:10px;margin-bottom:8px;overflow:hidden;background:var(--surface)}
.sfhead{display:flex;align-items:center;gap:10px;padding:12px 14px;cursor:pointer;user-select:none}
.sfhead:hover{background:var(--raised)}
.sfbody{display:none;padding:13px 16px 15px;border-top:1px solid var(--border);background:var(--bg)}
.sfinding.sopen .sfbody{display:block}.sfinding.sopen .schev{transform:rotate(90deg)}
.schev{color:var(--tx3);font-size:11px;transition:transform .2s;flex:none}
.sfent{font-size:12.5px;padding:4px 0;border-bottom:1px solid var(--border);line-height:1.5}
.sfent:last-child{border-bottom:0}
.sfblock{margin-top:10px}.sfblabel{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--tx3);margin-bottom:4px}
.sfblockbody{font-size:12.5px;color:var(--tx2);line-height:1.6}
.cmprow{padding:7px 0;font-size:13px;border-bottom:1px solid var(--border)}
.cmprow:last-child{border-bottom:0}
.sevpill{display:inline-block;font-size:10.5px;font-weight:700;padding:1px 8px;border-radius:999px;margin-right:6px}
.toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%);background:var(--raised);border:1px solid var(--border2);
border-radius:10px;padding:11px 18px;font-size:13px;opacity:0;transition:opacity .2s;pointer-events:none}
.toast.show{opacity:1}
.attack-chain{display:flex;align-items:flex-start;flex-wrap:wrap;gap:0;margin:6px 0 2px;overflow-x:auto}
.chain-node{background:var(--raised);border:1px solid var(--border2);border-radius:8px;padding:5px 9px;max-width:200px;flex:none}
.chain-kind{font-size:9.5px;color:var(--tx3);text-transform:uppercase;letter-spacing:.04em;font-family:var(--mono)}
.chain-name{font-size:11.5px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px}
.chain-start .chain-name{color:var(--low)}.chain-end .chain-name{color:var(--crit)}
.chain-arrow-wrap{display:flex;flex-direction:column;align-items:center;padding:0 4px;align-self:center;min-width:54px;max-width:130px}
.chain-edge-line{height:2px;background:var(--border2);width:100%}
.chain-tech{font-size:9.5px;color:var(--tx3);margin-top:3px;text-align:center;word-break:break-word;max-width:120px;line-height:1.3}
.cat-pill{font-size:10px;font-weight:600;color:var(--tx3);background:var(--raised);border:1px solid var(--border);border-radius:999px;padding:1px 8px}
.mitre-pill{font-size:10px;font-weight:600;color:#7a89c2;background:rgba(122,137,194,.12);border:1px solid rgba(122,137,194,.25);border-radius:999px;padding:1px 8px;font-family:var(--mono)}
.srctag.chain{background:rgba(242,92,112,.14);color:var(--crit)}
.sev-filter{display:flex;gap:5px;flex-wrap:wrap;margin-left:auto}
.sfbtn{background:var(--raised);border:1px solid var(--border);border-radius:8px;color:var(--tx2);font-size:11.5px;padding:4px 10px;cursor:pointer;font-weight:600}
.sfbtn span{color:var(--tx3);font-family:var(--mono);font-size:10.5px;margin-left:3px}
.sfbtn.on{background:var(--surface);border-color:var(--border2);color:var(--tx)}
.sfbtn[data-f="Critical"].on{border-color:rgba(242,92,112,.4);color:var(--crit)}
.sfbtn[data-f="High"].on{border-color:rgba(255,145,76,.35);color:var(--high)}
.sfbtn[data-f="Medium"].on{border-color:rgba(232,194,87,.35);color:var(--med)}
.sfbtn[data-f="Low"].on{border-color:rgba(91,179,224,.35);color:var(--low)}
.btn.sm{padding:6px 12px;font-size:12.5px}
.gtoolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:12px}
.gtoolbar select,.gtoolbar input{background:var(--surface);border:1px solid var(--border);color:var(--tx);border-radius:9px;padding:8px 11px;font-size:13px}
.gtoolbar input[type=search]{min-width:260px}
#gobj{flex:0 0 auto;width:auto;min-width:0;cursor:pointer}
.gvia{position:relative}
.gvia>summary{list-style:none;cursor:pointer;background:var(--surface);border:1px solid var(--border);color:var(--tx);border-radius:9px;padding:8px 11px;font-size:13px;white-space:nowrap;user-select:none}
.gvia>summary::-webkit-details-marker{display:none}
.gvia[open]>summary{border-color:var(--accent)}
.gvialist{position:absolute;z-index:50;top:calc(100% + 4px);left:0;min-width:220px;max-height:280px;overflow:auto;background:var(--surface);border:1px solid var(--border2);border-radius:10px;padding:6px;box-shadow:0 10px 30px rgba(0,0,0,.4)}
.gvialist label{display:flex;align-items:center;gap:8px;padding:6px 8px;border-radius:7px;font-size:12.5px;color:var(--tx);cursor:pointer}
.gvialist label:hover{background:var(--raised)}
.gvialist input{accent-color:var(--accent)}
.gvialist .gviaclear{width:100%;margin-top:4px}
.gsearchbox{position:relative}
.gsug{position:absolute;z-index:30;top:100%;left:0;right:0;background:var(--raised);border:1px solid var(--border);border-radius:9px;margin-top:4px;max-height:300px;overflow:auto}
.gsug>div{padding:8px 11px;cursor:pointer;border-bottom:1px solid var(--border)}
.gsug>div:hover{background:var(--surface)}
main.graphwide{max-width:1800px}
/* Embedded mode (graph shown inside the report's Attack Graph tab): drop the app chrome
   and the page heading so only the explorer fills the frame. */
body.embed header{display:none}
body.embed main{max-width:none;padding:10px 14px 14px}
body.embed main>h1,body.embed main>.sub{display:none}
/* Tier-0 selection step */
.t0grid{display:grid;grid-template-columns:1fr 340px;gap:16px;margin-top:14px}
@media(max-width:900px){.t0grid{grid-template-columns:1fr}}
.t0bar{display:flex;gap:8px;margin-bottom:10px}
.t0list{display:flex;flex-direction:column;gap:1px;max-height:52vh;overflow:auto}
.t0row{display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:9px;padding:7px 8px;border-radius:7px;cursor:pointer;border:1px solid transparent}
.t0row:hover{background:var(--hover);border-color:var(--border)}
.t0nm{color:var(--tx);font-size:12.5px;display:flex;align-items:center;gap:6px;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.t0dt{font-size:11px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-align:right}
.t0badge{font-size:9.5px;padding:1px 5px;border-radius:999px;background:rgba(229,72,77,.16);color:#F0A6AA;border:1px solid rgba(229,72,77,.35)}
.t0pager{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:8px;padding-top:8px;border-top:1px solid var(--border)}
.t0sel,.t0rec{display:flex;flex-direction:column;gap:2px;max-height:32vh;overflow:auto}
.t0side .k{color:var(--tx3);font-size:10.5px;text-transform:uppercase;letter-spacing:.07em;margin:15px 0 6px;font-weight:600}
.t0side .k:first-child{margin-top:0}
.gwrap{display:grid;grid-template-columns:300px 1fr 340px;gap:14px}
#cy{height:660px;background:#0A0C12;border:1px solid var(--border);border-radius:14px}
.gside{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:16px;font-size:13px;overflow:auto;max-height:660px}
#gdetail{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:16px;font-size:13px;overflow:auto;max-height:660px}
.gnodehead{display:flex;align-items:center;gap:9px;margin-bottom:2px}
.gside h3{margin:0;font-size:15px;word-break:break-word}
.gside .k,#gdetail .k{color:var(--tx3);font-size:10.5px;text-transform:uppercase;letter-spacing:.07em;margin-top:15px;margin-bottom:6px;font-weight:600}
.gside .k:first-child,#gdetail .k:first-child{margin-top:2px}
#gdetail h3{margin:0 0 2px}
.gactions{display:flex;flex-wrap:wrap;gap:7px}
.gprops{display:flex;flex-direction:column;gap:1px;background:var(--bg);border:1px solid var(--border);border-radius:9px;overflow:hidden}
.prow{display:flex;justify-content:space-between;gap:10px;padding:6px 10px;border-bottom:1px solid var(--border)}
.prow:last-child{border-bottom:none}
.pk{color:var(--tx3);font-size:11.5px;flex:none}
.pv{color:var(--tx);font-size:11.5px;text-align:right;word-break:break-word}
.gitem{padding:6px 10px;border-bottom:1px solid var(--border);color:var(--tx);font-size:11.5px;line-height:1.45;word-break:break-word}
.gitem:last-child{border-bottom:none}
.gtags{display:flex;flex-wrap:wrap;gap:5px}
.tagpill{background:var(--raised);border:1px solid var(--border);border-radius:6px;padding:2px 7px;font-size:10.5px;color:var(--tx2)}
.gid{font-family:ui-monospace,monospace;font-size:11px;word-break:break-all;color:var(--tx3);background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:7px 9px}
.t0reason{padding:7px 10px;border-bottom:1px solid var(--border)}
.t0reason:last-child{border-bottom:none}
.t0lbl{color:#F0A6AA;font-size:12px;font-weight:500}
.t0desc{color:var(--tx2);font-size:11.5px;line-height:1.5;margin-top:2px}
.linkbtn{background:none;border:none;color:var(--accent);cursor:pointer;font-size:11.5px;padding:0}
.gsearchbox{position:relative}
.glegend{display:flex;flex-wrap:wrap;gap:8px 14px;font-size:12px;color:var(--tx2)}
.glegend span{display:inline-flex;align-items:center;gap:6px}
.gdot{width:11px;height:11px;border-radius:50%;display:inline-block;flex:none}
.gmsg{color:var(--tx2);font-size:12.5px}
.gpresets{display:flex;flex-direction:column;gap:6px}
.qbtn{text-align:left;background:var(--surface);border:1px solid var(--border);color:var(--tx);border-radius:8px;padding:7px 10px;font-size:12.5px;cursor:pointer}
.qbtn:hover{background:var(--hover);border-color:var(--border2)}
.gsq{display:flex;align-items:center;gap:6px}
.gsq .qbtn{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.gpathlist{display:flex;flex-direction:column;gap:2px;max-height:240px;overflow:auto}
.gpath{display:flex;flex-direction:column;gap:1px;padding:6px 8px;border-radius:7px;cursor:pointer;border:1px solid transparent}
.gpath:hover{background:var(--hover);border-color:var(--border)}
.gpk{color:var(--tx);font-size:12px;display:flex;align-items:center;gap:5px}
.gph{color:var(--tx3);font-size:11px}
#gstage:fullscreen{background:var(--bg);padding:16px;overflow:auto}
#gstage:fullscreen #cy{height:calc(100vh - 150px)}
#gstage:fullscreen .gside{max-height:calc(100vh - 150px)}
@media(max-width:1280px){.gwrap{grid-template-columns:270px 1fr}#gdetail{grid-column:1/-1;max-height:340px}}
@media(max-width:900px){.gwrap{grid-template-columns:1fr}#cy{height:460px}.gside,#gdetail{max-height:none}}
</style></head><body>
<header><span class="mark"><svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg" width="30" height="30" aria-hidden="true"><defs><linearGradient id="phbg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#F09432"/><stop offset="100%" stop-color="#C05C08"/></linearGradient></defs><rect width="32" height="32" rx="8" fill="url(#phbg)"/><ellipse cx="9" cy="21" rx="4" ry="10" fill="#0b0d14"/><ellipse cx="23" cy="21" rx="4" ry="10" fill="#0b0d14"/><circle cx="16" cy="13" r="9.5" fill="#0b0d14"/><circle cx="12" cy="12" r="2.4" fill="#F09432"/><circle cx="20" cy="12" r="2.4" fill="#F09432"/><circle cx="12" cy="12" r="0.9" fill="#0b0d14"/><circle cx="20" cy="12" r="0.9" fill="#0b0d14"/><ellipse cx="16" cy="19.5" rx="3" ry="2.2" fill="#5a2a04"/></svg></span><div><div class="bn">PostureHound</div><div class="bs">Azure identity posture</div></div>
<nav>
 <a href="#/dashboard" data-r="dashboard">Dashboard</a>
 <a href="#/scan" data-r="scan">New scan</a>
 <a href="#/history" data-r="history">History</a>
 <a href="#/graph" data-r="graph">Attack Graph</a>
 <a href="#/rules" data-r="rules">Rules</a>
 <a href="#/traces" data-r="traces">AI Traces</a>
 <a href="#/settings" data-r="settings">Settings</a>
</nav>
<span class="keypill" id="keypill">AI key: not set</span>
<button class="logout" id="btnLogout" type="button" title="Sign out">Log out</button>
</header>
<div class="pwbanner" id="pwbanner" hidden>You are using the default password. <a href="#/settings">Change it in Settings ↗</a></div>
<main id="app"></main>
<div class="toast" id="toast"></div>
<script src="/static/vendor/cytoscape.min.js"></script>
<script src="/static/vendor/dagre.min.js"></script>
<script src="/static/vendor/cytoscape-dagre.min.js"></script>
<script src="/static/vendor/layout-base.js"></script>
<script src="/static/vendor/cose-base.js"></script>
<script src="/static/vendor/cytoscape-fcose.min.js"></script>
<script nonce="__NONCE__">
const $=s=>document.querySelector(s);
const qa=(s,r=document)=>Array.prototype.slice.call(r.querySelectorAll(s));
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const gradeClass=g=>'g'+(g||'F').charAt(0);
function toast(m){const t=$('#toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2600);}
async function api(path,opts){const r=await fetch(path,opts);if(r.status===401){_showLogin();throw new Error('Not authenticated');}if(!r.ok){let d='';try{d=(await r.json()).detail||'';}catch(e){}throw new Error(d||('HTTP '+r.status));}return r.json();}
// Login screen (shown on boot when unauthenticated, and whenever any API call returns 401).
function _showLogin(msg){
  document.body.classList.add('locked');
  const bn=$('#pwbanner'); if(bn)bn.hidden=true;
  const app=$('#app'); if(!app)return;
  app.innerHTML=`<div class="loginwrap"><form id="loginform" class="card loginbox">
    <h1 style="margin:0 0 2px;font-size:20px">Sign in</h1>
    <p class="sub" style="margin:0 0 18px">PostureHound - Azure identity posture</p>
    <label class="fl">Username<input id="lu" autocomplete="username" required></label>
    <label class="fl">Password<input id="lp" type="password" autocomplete="current-password" required></label>
    <div class="loginerr" id="lerr">${esc(msg||'')}</div>
    <button class="btn" type="submit" style="width:100%">Sign in</button>
  </form></div>`;
  $('#loginform').onsubmit=async e=>{
    e.preventDefault();
    const u=$('#lu').value.trim(),p=$('#lp').value;
    try{const r=await fetch('/api/auth/login',{method:'POST',body:new URLSearchParams({username:u,password:p})});
      if(!r.ok){let d={};try{d=await r.json();}catch(_){}$('#lerr').textContent=d.detail||('Sign-in failed ('+r.status+')');return;}
      location.reload();
    }catch(err){$('#lerr').textContent=err.message;}
  };
  const lu=$('#lu'); if(lu)lu.focus();
}
async function _logout(){try{await fetch('/api/auth/logout',{method:'POST'});}catch(e){}location.reload();}
// Boot: decide login vs app based on the session, then run the router.
async function _boot(){
  let me={authenticated:true,must_change:false};
  try{me=await api('/api/auth/me');}catch(e){return;}   // 401 path already showed login
  if(me&&me.authenticated===false){_showLogin();return;}
  document.body.classList.remove('locked');
  const bn=$('#pwbanner'); if(bn)bn.hidden=!me.must_change;
  const lo=$('#btnLogout'); if(lo)lo.onclick=_logout;
  refreshKeyPill();router();
}
function delBtn(b,onDone){
  if(!b._dconf){b._dconf=setTimeout(()=>{b._dconf=null;b.textContent='Delete';},3000);b.textContent='Sure?';return;}
  clearTimeout(b._dconf);b._dconf=null;b.disabled=true;b.textContent='Deleting…';
  fetch('/api/scans/'+b.dataset.del,{method:'DELETE'})
    .then(r=>r.ok?r.json():r.json().catch(()=>({})).then(d=>{throw new Error(d.detail||('HTTP '+r.status));}))
    .then(()=>{toast('Deleted.');onDone();})
    .catch(e=>{toast('Delete failed: '+e.message);b.disabled=false;b.textContent='Delete';});
}
function setNav(route){document.querySelectorAll('nav a').forEach(a=>a.classList.toggle('on',a.dataset.r===route));}
async function refreshKeyPill(){try{const s=await api('/api/settings');const p=$('#keypill');const src=s.api_key_source;p.textContent='AI key: '+(src==='env'?'from .env':src==='settings'?'set':'not set');p.classList.toggle('on',s.api_key_set);}catch(e){}}

function fmtDate(ts){if(!ts)return '\u2014';const d=new Date(ts*1000);return d.toLocaleString();}

// ---- Dashboard ----------------------------------------------------------
async function viewDashboard(){
 const app=$('#app');app.innerHTML='<h1>Dashboard</h1><p class="sub">Posture across your scans.</p><div id="db">Loading\u2026</div>';
 let scans=[];try{scans=await api('/api/scans');}catch(e){}
 if(!scans.length){$('#db').innerHTML='<div class="card empty">No scans yet. <a href="#/scan">Run your first scan \u2192</a></div>';return;}
 const latest=scans[0];const p=latest.score||0;
 const tiles=[['Latest grade',latest.grade||'\u2014'],['Critical',latest.critical],['High',latest.high],
   ['Findings',latest.findings],['Remediated',`${latest.resolved||0}/${latest.findings} (${latest.remediation_pct||0}%)`],['Scans stored',scans.length]];
 $('#db').innerHTML=`
  <div class="card hero">
    <div class="ring" style="--p:${p}"><div class="inner"><div class="g">${esc(latest.grade||'?')}</div><div class="s">${p}/100</div></div></div>
    <div><div class="pt"><b>Latest scan</b> \u00B7 ${esc((latest.files||[]).join(', ')||'collection')}</div>
    <div class="pt muted small">${fmtDate(latest.created_at)}</div>
    ${latest.complete?'':'<div class="banner" style="margin-top:10px">Collection may be incomplete \u2014 open the report\u2019s Coverage tab.</div>'}
    <div style="margin-top:12px"><a class="btn" href="/api/scans/${latest.id}/report" target="_blank">Open full report \u2197</a> <a class="btn ghost" href="/api/scans/${latest.id}/report#roadmap" target="_blank">Action plan \u2197</a></div></div>
  </div>
  <div class="tiles">${tiles.map(t=>`<div class="tile"><div class="n">${esc(t[1])}</div><div class="l">${esc(t[0])}</div></div>`).join('')}</div>
  ${scans.length>1?`<div class="card"><h1 style="font-size:15px;margin:0 0 10px">Posture trend</h1>${trendSVG(scans)}</div>`:''}
  <div id="evalpanel" class="card">Loading detailed evaluation\u2026</div>
  ${scans.length>1?`<div class="card"><h1 style="font-size:15px;margin:0 0 2px">Previous scans</h1><div style="margin-top:6px">${recentScanCards(scans.slice(1,7))}</div></div>`:''}`;
 renderEvalPanel(latest.id);
 qa('[data-del]',$('#db')).forEach(b=>b.onclick=()=>delBtn(b,viewDashboard));
}

function trendSVG(scans){
 const pts=[...scans].filter(s=>s.created_at).sort((a,b)=>a.created_at-b.created_at).slice(-20);
 if(pts.length<2) return '<div class="muted small">Run at least two scans to see a trend.</div>';
 const W=680,H=120,pad=16;
 const xs=(i)=>pad+(i/(pts.length-1))*(W-pad*2);
 const ys=(v)=>H-pad-(v/100)*(H-pad*2);
 const path=pts.map((p,i)=>`${i===0?'M':'L'}${xs(i).toFixed(1)},${ys(p.score||0).toFixed(1)}`).join(' ');
 const dots=pts.map((p,i)=>`<circle cx="${xs(i).toFixed(1)}" cy="${ys(p.score||0).toFixed(1)}" r="3.5" fill="var(--accent)"><title>${esc(fmtDate(p.created_at))} \u2014 ${esc(p.grade)} (${p.score})</title></circle>`).join('');
 const first=pts[0].score||0, last=pts[pts.length-1].score||0, delta=last-first;
 const deltaCol=delta>0?'var(--ok)':delta<0?'var(--crit)':'var(--tx3)';
 return `<svg viewBox="0 0 ${W} ${H}" width="100%" style="max-width:100%" xmlns="http://www.w3.org/2000/svg">
   <line x1="${pad}" y1="${ys(75)}" x2="${W-pad}" y2="${ys(75)}" stroke="var(--border)" stroke-dasharray="3,3"/>
   <path d="${path}" fill="none" stroke="var(--accent)" stroke-width="2"/>
   ${dots}
 </svg><div class="small muted" style="margin-top:4px">${pts.length} scans shown \u00B7 <b style="color:${deltaCol}">${delta>0?'+':''}${delta} pts</b> since the first of these</div>`;
}

async function renderEvalPanel(scanId){
 const el=$('#evalpanel'); if(!el) return;
 let full=null; try{full=await api('/api/scans/'+scanId);}catch(e){}
 if(!full){el.innerHTML='<div class="muted small">Could not load the detailed evaluation for this scan.</div>';return;}
 const findings=full.findings||[];
 const nonPathFindings=findings.filter(f=>f.source!=='path_consolidation');
 const attackPathCount=findings.length-nonPathFindings.length;
 const sevRank={Critical:0,High:1,Medium:2,Low:3,Info:4};
 const top=nonPathFindings.filter(f=>!f.best_practice).sort((a,b)=>(sevRank[a.severity]??5)-(sevRank[b.severity]??5)).slice(0,5);
 const gradeCol=full.score.score<40?'var(--crit)':full.score.score<75?'var(--med)':'var(--ok)';
 let pipeline='';
 if(full.ai_enabled){
   pipeline=`<div class="evalpipeline">
     <span class="steplabel">${esc(full.ai_sonnet_model||'Sonnet')} <span class="stepsub">${Object.keys(full.ai_specialist_counts||{}).length||17} specialists</span></span>
     <span class="stepcount">${full.ai_sonnet_raw_count||0} proposed</span>
     <span class="arrow">\u2192</span>
     <span class="steplabel">${esc(full.ai_opus_model||full.ai_sonnet_model||'Opus')} <span class="stepsub">synthesizer + correlator</span></span>
     <span class="arrow">\u2192</span>
     <span class="steplabel">${esc(full.ai_haiku_model||'Sonnet')} <span class="stepsub">Phase 4 skeptic</span></span>
     <span class="stepcount">${full.ai_generated_count||0} final</span>
   </div>
   <div class="small muted" style="margin-top:6px">${full.ai_rejected_count?`${full.ai_rejected_count} candidate(s) rejected \u2014 referenced something not present in this tenant's data. `:''}${full.deterministic_finding_count||0} deterministic safety-net findings included alongside the AI review.</div>`;
 } else if(full.ai_error){
   pipeline=`<div class="banner warn" style="margin:0"><span class="small">${esc(full.ai_error)}</span></div>`;
 } else {
   pipeline=`<div class="small muted">AI review was not run for this scan. <a href="#/scan">Run a new scan</a> with "Add AI-powered analysis" checked to get the Sonnet specialists + Haiku skeptic review.</div>`;
 }
 const findingRows=top.map(f=>{
   const isAI=f.source==='ai_generated';
   const reasoning=(f.reasoning||f.what||'').slice(0,220);
   return `<div class="evalfinding">
     <div class="efhead"><span class="sevdot" style="background:${SEVCOL[f.severity]||'#888'}"></span>
       <b>${esc(f.title)}</b>
       <span class="srctag ${isAI?'ai':'det'}" style="margin-left:auto">${isAI?'\u2726 AI':'\u2699 rule'}</span></div>
     <div class="small muted" style="margin-top:4px">${esc(f.category)} \u00B7 ${(f.entities||[]).length} affected</div>
     ${reasoning?`<div class="small" style="margin-top:6px;line-height:1.5">${esc(reasoning)}${(f.reasoning||f.what||'').length>220?'\u2026':''}</div>`:''}
   </div>`;
 }).join('') || '<div class="muted small">No active findings above best-practice severity.</div>';
 el.innerHTML = `<h1 style="font-size:15px;margin:0 0 4px">Detailed evaluation</h1>
   <p class="sub" style="margin:0 0 14px;font-size:13px">Posture <b style="color:${gradeCol}">${esc(full.score.grade)}</b> (${full.score.score}/100) \u00B7 ${nonPathFindings.length} finding(s)${attackPathCount?` \u00B7 ${attackPathCount} attack path(s)`:''}</p>
   ${pipeline}
   <div style="margin-top:16px">${findingRows}</div>
   <div style="margin-top:14px"><a class="btn ghost" style="padding:8px 14px;font-size:12.5px" href="/api/scans/${scanId}/report" target="_blank">Open full report with reasoning &amp; evidence \u2197</a>
     <a class="btn ghost" style="padding:8px 14px;font-size:12.5px" href="/api/scans/${scanId}/report#roadmap" target="_blank">Action plan \u2197</a></div>`;
}
const SEVCOL={Critical:'#F25C70',High:'#FF914C',Medium:'#E8C257',Low:'#5BB3E0',Info:'#5C667E'};

// ---- Scan ---------------------------------------------------------------
let scanFiles = [];
function fmtSize(n){ if(n>=1e9) return (n/1e9).toFixed(1)+' GB'; if(n>=1e6) return (n/1e6).toFixed(1)+' MB'; if(n>=1e3) return (n/1e3).toFixed(1)+' KB'; return n+' B'; }
function renderFileList(){
 const el=$('#filelist'); if(!el) return;
 if(!scanFiles.length){el.innerHTML='';return;}
 el.innerHTML=scanFiles.map((f,i)=>`<div class="fileitem"><span class="fn">${esc(f.name)}</span><span class="fs">${fmtSize(f.size)}</span><button class="rmfile" data-i="${i}" title="Remove">\u00D7</button></div>`).join('');
 qa('.rmfile',el).forEach(b=>b.onclick=()=>{scanFiles.splice(+b.dataset.i,1);renderFileList();});
}
function renderScanResults(full,scanId){
 const sc=full.score||{};
 const active=(full.findings||[]).filter(f=>!f.best_practice);
 const bpN=(full.findings||[]).filter(f=>f.best_practice).length;
 // Order: severity first, then blast radius (a chokepoint covering 234 principals outranks a
 // 2-path individual at the same severity), then confidence, so the most consequential and
 // consolidated findings sit at the top.
 {const _sr={Critical:0,High:1,Medium:2,Low:3,Info:4};
  const _impact=f=>(f.member_count||f.path_count||(f.entities?f.entities.length:0)||0);
  active.sort((a,b)=>(_sr[a.severity]??5)-(_sr[b.severity]??5) || _impact(b)-_impact(a) || ((b.confidence??0)-(a.confidence??0)));}
 // Recompute from findings directly - stored severity_counts may predate the
 // path_consolidation exclusion fix (those findings render in the Attack Paths tab).
 const sev=(()=>{const c={Critical:0,High:0,Medium:0,Low:0,Info:0};for(const f of (full.findings||[])){if(f.source==='path_consolidation')continue;if(c[f.severity]!==undefined)c[f.severity]++;}return c;})();
 const gradeCol=sc.score<40?'var(--crit)':sc.score<75?'var(--med)':'var(--ok)';
 function sevCol(s){return {Critical:'var(--crit)',High:'var(--high)',Medium:'var(--med)',Low:'var(--low)',Info:'var(--tx3)'}[s]||'#888';}
 function confCol(c){if(c==null)return 'var(--tx3)';return c>=85?'var(--ok)':c>=60?'var(--med)':'var(--high)';}
 function _renderChainNodes(hops,labelPrefix){
   if(!hops||!hops.length) return '';
   const parts=[];
   hops.forEach((hop,i)=>{
     const fromName=(hop.from&&(hop.from.name||hop.from.id))||'?';
     const toName=(hop.to&&(hop.to.name||hop.to.id))||'?';
     const fromKind=(hop.from&&hop.from.kind)||'';
     const toKind=(hop.to&&hop.to.kind)||'';
     const tech=hop.technique||hop.via||'';
     if(i===0) parts.push(`<div class="chain-node chain-start">${fromKind?`<div class="chain-kind">${esc(fromKind.replace('AZ',''))}</div>`:''}
       <div class="chain-name" title="${esc(fromName)}">${esc(fromName)}</div></div>`);
     parts.push(`<div class="chain-arrow-wrap"><div class="chain-edge-line"></div><div class="chain-tech">${esc(tech)}</div></div>`);
     const isLast=i===hops.length-1;
     parts.push(`<div class="chain-node${isLast?' chain-end':''}"${(hop.to&&hop.to.tier0)?' style="border-color:rgba(196,111,255,.4)"':''}>
       ${toKind?`<div class="chain-kind">${esc(toKind.replace('AZ',''))}</div>`:''}
       <div class="chain-name" title="${esc(toName)}">${esc(toName)}</div></div>`);
   });
   return parts.join('');
 }
 function renderChain(chain){
   if(!chain||!chain.length) return '';
   return `<div class="sfblock"><div class="sfblabel">⛓ Attack path - ${chain.length} hop${chain.length!==1?'s':''}</div><div class="attack-chain">${_renderChainNodes(chain,'')}</div></div>`;
 }
 // Deep-link to the attack graph plotting THIS finding's own path (entry -> its target), not a
 // generic path to Tier-0. Returns '' when the finding has no distinct target to trace to.
 function _graphHref(scanId,f){
   const mp=f.max_impact_path||{}; const eid=(mp.entry||{}).id; const tid=(mp.target||{}).id;
   const base='#/graph/'+encodeURIComponent(scanId);
   if(eid&&tid&&(mp.length||0)>0&&tid!==eid) return base+'/'+encodeURIComponent(eid)+'/'+encodeURIComponent(tid);
   const e0=(f.entities||[])[0]&&(f.entities||[])[0].id;
   return e0?base+'/'+encodeURIComponent(e0):'';
 }
 const cards=active.map(f=>{
   const col=sevCol(f.severity);
   const conf=f.confidence;
   const src=f.source==='ai_chain'?{label:'⛓ Chain',cls:'chain'}:f.source==='ai_generated'?{label:'◆ AI',cls:'ai'}:{label:'⚙ Rule',cls:'det'};
   const summary=f.summary||(f.what||'').slice(0,200);
   const ents=(f.entities||[]).slice(0,15).map(e=>{
     const ev=e.role_in_finding||(e.evidence&&typeof e.evidence==='object'?Object.entries(e.evidence).slice(0,2).map(([k,v])=>`${esc(k)}: ${esc(String(v))}`).join(' · '):'');
     return `<div class="sfent"><b class="mono">${esc(e.name||e.id||'')}</b> <span class="muted">${esc((e.kind||'').replace('AZ',''))}</span>${ev?` <span class="muted small">- ${esc(ev)}</span>`:''}</div>`;
   }).join('');
   const evList=(f.evidence||[]).map(e=>`<li>${esc(e)}</li>`).join('');
   const scenario=f.attack_scenario||(f.detail||{}).scenario||'';
   const fix=f.remediation||((f.detail||{}).steps||[]).join(' ');
   const detection=f.detection||'';
   const chainHtml=renderChain(f.escalation_chain);
   const mitrePill=f.mitre_technique?`<span class="mitre-pill">${esc(f.mitre_technique)}</span>`:'';
   const explLabel=f.exploitability?`<span class="cat-pill">⚡ ${esc(f.exploitability)}</span>`:'';
   return `<div class="sfinding" data-sev="${esc(f.severity)}">
    <div class="sfhead">
      <span style="width:3px;align-self:stretch;border-radius:2px;background:${col};flex:none;margin:-12px 4px -12px -14px"></span>
      <div style="flex:1;min-width:0">
        <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:3px">
          <span style="font-size:10.5px;font-weight:700;color:${col}">${esc(f.severity)}</span>
          <span class="srctag ${src.cls}">${src.label}</span>
          ${f.category?`<span class="cat-pill">${esc(f.category)}</span>`:''}${mitrePill}${explLabel}
        </div>
        <b style="display:block;line-height:1.3">${esc(f.title)}</b>
        ${summary?`<div style="font-size:12px;color:var(--tx2);margin-top:3px;line-height:1.45">${esc(summary.slice(0,200))}${summary.length>200?'…':''}</div>`:''}
      </div>
      <div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px;flex:none;margin-left:10px">
        ${conf!=null?`<span style="font-size:11px;font-weight:700;color:${confCol(conf)};font-family:var(--mono)">${conf}%</span>`:''}
        <span class="small muted">${(f.entities||[]).length} affected</span>
      </div>
      <span class="schev">▶</span>
    </div>
    <div class="sfbody">
      <div style="color:var(--tx2);font-size:13px;line-height:1.65;margin-bottom:10px">${esc(f.what||f.why_it_matters||'')}</div>
      ${chainHtml}
      ${scenario?`<div class="sfblock"><div class="sfblabel">Attack scenario</div><div class="sfblockbody">${esc(scenario)}</div></div>`:''}
      ${detection?`<div class="sfblock"><div class="sfblabel">Detection signals</div><div class="sfblockbody">${esc(detection)}</div></div>`:''}
      ${ents?`<div class="sfblock"><div class="sfblabel">Affected entities</div>${ents}</div>`:''}
      ${evList?`<div class="sfblock"><div class="sfblabel">Evidence</div><ul style="margin:4px 0;padding-left:18px;color:var(--tx2);font-size:12.5px">${evList}</ul></div>`:''}
      ${fix?`<div class="sfblock"><div class="sfblabel">How to fix</div><div class="sfblockbody">${esc(fix)}</div></div>`:''}
      <div style="margin-top:12px;display:flex;gap:7px;flex-wrap:wrap">
        <a class="btn ghost" style="font-size:11.5px;padding:5px 11px" href="/api/scans/${scanId}/report#findings" target="_blank">Full detail in report ↗</a>
        ${_graphHref(scanId,f)?`<a class="btn ghost" style="font-size:11.5px;padding:5px 11px" href="${_graphHref(scanId,f)}">◆ View in attack graph</a>`:''}
      </div>
    </div>
   </div>`;
 }).join('');
 // Top chokepoints - the nodes that the most attack paths pass through or converge on;
 // fixing one severs the most paths. Sourced from the deterministic choke_points analysis.
 const chokeSrc=((full.analytics||{}).choke_points)||[];
 const chokeRows=chokeSrc.slice(0,6).map((c,i)=>{
   const n=(c.path_count!=null)?c.path_count:(c.paths_through!=null?c.paths_through:0);
   return `<div style="display:flex;gap:8px;align-items:baseline;font-size:12px;padding:2px 0">
     <span class="muted" style="min-width:15px">${i+1}.</span>
     <span style="font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(c.name||c.id||'?')}</span>
     ${c.kind?`<span class="muted" style="font-size:11px">${esc(c.kind)}</span>`:''}
     <span style="margin-left:auto;color:var(--med);white-space:nowrap">${n} path${n!==1?'s':''}</span>
   </div>`;}).join('');
 const bhChokeBlock=chokeRows?`<div style="margin-top:10px;padding-top:8px;border-top:1px solid var(--border)">
   <div class="small muted" style="margin-bottom:3px">Top chokepoints - fixing one severs the most attack paths:</div>
   ${chokeRows}</div>`:'';
 const res=document.createElement('div');
 res.innerHTML=`<div class="card" style="margin-top:16px;display:flex;gap:18px;align-items:center;flex-wrap:wrap">
  <div style="text-align:center;min-width:90px;padding-right:18px;border-right:1px solid var(--border)">
    <div style="font-size:50px;font-weight:800;line-height:1;color:${gradeCol}">${esc(sc.grade||'?')}</div>
    <div class="small muted">${sc.score||0}/100</div>
  </div>
  <div style="flex:1;min-width:160px">
    <div style="font-size:15px;font-weight:700">Scan complete</div>
    <div class="small muted" style="margin:4px 0 8px">${(full.findings||[]).filter(f=>f.source!=='path_consolidation').length} finding(s) · ${sev.Critical||0} critical · ${sev.High||0} high · ${sev.Medium||0} medium</div>
    ${bhChokeBlock}
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px">
      <a class="btn" style="font-size:12.5px;padding:6px 13px" href="/api/scans/${scanId}/report" target="_blank">Open executive report ↗</a>
      <a class="btn ghost" style="font-size:12.5px;padding:6px 13px" href="/api/scans/${scanId}/export.csv">Download CSV</a>
      <button class="btn ghost" style="font-size:12.5px;padding:6px 13px" data-action="goto-history">History</button>
    </div>
  </div>
 </div>
 <div style="margin:22px 0 10px;display:flex;align-items:center;gap:10px;flex-wrap:wrap">
   <div style="font-size:14px;font-weight:700">Findings</div>
   <div class="small muted">${active.length} active${bpN?` · ${bpN} best-practice`:''}${active.length?` - click to expand`:''}</div>
   <div class="sev-filter" id="sfilt">
     <button class="sfbtn on" data-f="All">All <span>${active.length}</span></button>
     ${['Critical','High','Medium','Low','Info'].filter(s=>(sev[s]||0)>0).map(s=>`<button class="sfbtn" data-f="${s}">${s} <span>${sev[s]}</span></button>`).join('')}
   </div>
 </div>
 <div id="sfcards">${active.length?cards:'<div class="card empty">No active findings. Excellent posture.</div>'}</div>
 ${bpN?`<div class="small muted" style="margin-top:8px">${bpN} best-practice recommendation(s) in the full report.</div>`:''}`;
 $('#app').appendChild(res);
 res.querySelectorAll('[data-action="goto-history"]').forEach(btn=>{
   btn.onclick=()=>{location.hash='#/history';};
 });
 res.querySelectorAll('.sfbtn').forEach(btn=>{
   btn.onclick=()=>{
     res.querySelectorAll('.sfbtn').forEach(b=>b.classList.remove('on'));
     btn.classList.add('on');
     const f=btn.dataset.f;
     res.querySelectorAll('.sfinding').forEach(el=>{el.style.display=(f==='All'||el.dataset.sev===f)?'':'none';});
   };
 });
 res.querySelectorAll('.sfinding').forEach(c=>c.querySelector('.sfhead').onclick=()=>c.classList.toggle('sopen'));
}
async function viewScan(){
 const app=$('#app');let st={};try{st=await api('/api/settings');}catch(e){}
 let prevScans=[];try{prevScans=(await api('/api/scans')).filter(s=>s.has_collection);}catch(e){}
 scanFiles=[];
 app.innerHTML=`<h1>New scan</h1><p class="sub">Upload your AzureHound collection \u2014 a single file, several together (ad.json and rm.json), or a .zip.</p>
 <div class="card">
   <div class="drop" id="dropzone">
     <div class="dropicon">\u2913</div>
     <div>Drag files here, or <label for="files" class="filelabel">browse</label></div>
     <input type="file" id="files" accept=".json,.ndjson,.zip" multiple style="display:none">
     <div class="hint">Files are analysed in memory and never written to disk. Select ad.json and rm.json together to merge both planes.</div>
   </div>
   <div id="filelist" class="filelist"></div>
   ${!st.api_key_set?'<div class="hint" style="color:var(--high);margin-top:10px">No AI key configured \u2014 <a href="#/settings" style="color:var(--high)">set it in Settings</a> before running. AI analysis requires an Anthropic key.</div>':''}
   <div class="hint" style="margin-top:10px;color:var(--tx3)">${st.arg_configured?'\u25c6 Or <b>collect the tenant live</b> from your read-only service principal \u2014 no upload needed. This reads the directory + Azure RBAC graph and assesses the whole tenant across all subscriptions.':'Tip: configure a read-only service principal in <a href="#/settings">Settings</a> to collect the tenant live, with no AzureHound upload.'}</div>
   <div style="margin-top:18px"><button id="run">Evaluate posture</button> ${st.arg_configured?'<button id="runlive" class="ghost" style="border-color:rgba(196,111,255,.45);color:#c46fff">\u25c6 Collect live from SP</button>':''} <button id="stopscan" class="ghost" style="display:none;border-color:rgba(242,92,112,.4);color:var(--crit)">&#9632; Stop scan</button> <span id="status" class="small muted"></span></div>
   <div id="livelog" class="livelog" style="display:none">
     <div class="livelogtitle">Live analysis log</div>
     <div id="logbody" class="logbody"></div>
   </div>
 </div>
 ${prevScans.length?`<div class="card">
   <div class="k" style="margin-top:0">Re-run from a previous collection</div>
   <p class="hint" style="margin:0 0 10px">Re-assess a tenant you already collected - no re-collection from Azure. Useful to try different Tier-0 selections or pick up engine changes.</p>
   <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
     <select id="prevsel" class="hsort" style="flex:1;min-width:280px">${prevScans.map(s=>`<option value="${esc(s.id)}">${esc(fmtDate(s.created_at))} · ${esc(s.grade||'?')} (${s.score||0}) · ${esc((s.files||[]).join(', ')||s.id)}</option>`).join('')}</select>
     <button id="prevrescan">⚡ Re-scan (no AI)</button>
     <button id="prevrun" class="ghost">Use this collection${st.api_key_set?' (with AI, pick Tier-0)':''}</button>
   </div>
   <div class="hint" style="margin:8px 0 0;color:var(--tx3)">⚡ <b>Re-scan (no AI)</b> re-runs the deterministic engine over the stored collection in one click - no Azure re-collection, no Tier-0 step, no AI cost. Use it to pick up rule/engine changes on data you already have.</div>
 </div>`:''}`;
 const dz=$('#dropzone');
 dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('over');});
 dz.addEventListener('dragleave',()=>dz.classList.remove('over'));
 dz.addEventListener('drop',e=>{e.preventDefault();dz.classList.remove('over');
   for(const f of e.dataTransfer.files) scanFiles.push(f); renderFileList();});
 $('#files').onchange=e=>{for(const f of e.target.files) scanFiles.push(f); renderFileList(); e.target.value='';};
 const setRunDisabled=(v)=>{ ['#run','#runlive','#prevrun'].forEach(s=>{const b=$(s);if(b)b.disabled=v;}); };
 // Poll a background job, streaming its log into #logbody. Resolves with the finished
 // job status ({done, scan_id, error, meta}). Shared by collect and assess phases.
 async function _pollJob(startCall,label){
   setRunDisabled(true);$('#status').innerHTML='<span class="spin"></span> '+(label||'working')+'\u2026';
   const logEl=$('#livelog'), body=$('#logbody'); if(logEl)logEl.style.display='block'; if(body)body.innerHTML='';
   const appendLines=(lines)=>{ if(!body)return; for(const l of lines){ const row=document.createElement('div'); row.className='logrow';
     row.innerHTML=`<span class="logt">${new Date(l.t*1000).toLocaleTimeString()}</span><span class="logm"></span>`;
     row.querySelector('.logm').textContent=l.message; body.appendChild(row); }
     body.scrollTop=body.scrollHeight; };
   const stopBtn=$('#stopscan');
   const start=await startCall();
   const jobId=start.job_id;
   if(stopBtn){stopBtn.style.display='';stopBtn.disabled=false;stopBtn.onclick=async()=>{stopBtn.disabled=true;try{await api('/api/jobs/'+jobId+'/cancel',{method:'POST'});}catch(e){}}}
   let seen=0, res=null;
   while(true){
     const st2=await api(`/api/jobs/${jobId}?since=${seen}`);
     if(st2.log && st2.log.length){ appendLines(st2.log); seen=st2.log_count; }
     if(st2.done){ res=st2; break; }
     await new Promise(r=>setTimeout(r,500));
   }
   if(stopBtn)stopBtn.style.display='none';
   return res;
 }
 // Assessment phase: run the pipeline, then show the report.
 async function driveAssess(startCall){
   try{
     const res=await _pollJob(startCall,'analysing');
     if(res.error || !res.scan_id){ $('#status').textContent='Error: '+(res.error||'scan failed'); setRunDisabled(false); return; }
     setRunDisabled(false); $('#status').textContent='';
     try{ renderScanResults(await api('/api/scans/'+res.scan_id),res.scan_id); }
     catch(e){ toast('Scan complete.'); setTimeout(()=>{ location.hash='#/history'; },400); }
   }catch(e){ const s=$('#stopscan'); if(s)s.style.display='none'; $('#status').textContent='Error: '+e.message; setRunDisabled(false); }
 }
 // Collect phase: gather the tenant, then open the optional Tier-0 selection step.
 async function driveCollect(startCall,useAi){
   try{
     const res=await _pollJob(startCall,'collecting');
     const cid=res.meta&&res.meta.collection_id;
     if(res.error || !cid){ $('#status').textContent='Error: '+(res.error||'collection failed'); setRunDisabled(false); return; }
     setRunDisabled(false); $('#status').textContent='';
     viewTier0Select(cid,useAi);
   }catch(e){ const s=$('#stopscan'); if(s)s.style.display='none'; $('#status').textContent='Error: '+e.message; setRunDisabled(false); }
 }
 $('#run').onclick=()=>{
   if(!scanFiles.length){toast('Choose at least one file, or use "Collect live from SP".');return;}
   const fd=new FormData();for(const f of scanFiles)fd.append('files',f);
   driveCollect(()=>api('/api/collect/start',{method:'POST',body:fd}),true);
 };
 if($('#runlive')) $('#runlive').onclick=()=>{
   driveCollect(()=>api('/api/collect/start-live',{method:'POST',body:new FormData()}),true);
 };
 if($('#prevrun')) $('#prevrun').onclick=()=>{
   const sid=$('#prevsel').value; if(!sid)return;
   const fd=new FormData();fd.append('scan_id',sid);
   driveCollect(()=>api('/api/collect/from-scan',{method:'POST',body:fd}),true);
 };
 // One-click deterministic re-scan of a stored collection - straight to assessment,
 // no Tier-0 step, AI off. Reuses the same job-polling + report-render path.
 if($('#prevrescan')) $('#prevrescan').onclick=()=>{
   const sid=$('#prevsel').value; if(!sid)return;
   const fd=new FormData();fd.append('scan_id',sid);fd.append('use_ai','false');
   driveAssess(()=>api('/api/assess/from-scan',{method:'POST',body:fd}));
 };
}

// \u2500\u2500 Optional Tier-0 selection step (after collect, before assessment) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
async function viewTier0Select(cid,useAi){
 const app=$('#app');
 app.innerHTML=`<h1>Select Tier-0 assets <span class="muted" style="font-size:15px;font-weight:400">\u2014 optional</span></h1>
   <p class="sub">Mark the crown-jewel assets for <b>this scan</b>. Auto-detected Tier-0 (privileged roles, Owner/UAA groups) are always included and pre-selected; browse any category to add your own. Then run the assessment \u2014 or skip to use the recommended set only.</p>
   <div id="t0err" class="muted small" style="color:var(--high)"></div>
   <div class="t0grid">
     <div class="t0browse card">
       <div class="t0bar">
         <select id="t0cat" class="hsort"></select>
         <input id="t0q" type="search" placeholder="Search this category\u2026" autocomplete="off" class="hsort" style="flex:1">
       </div>
       <div id="t0list" class="t0list muted small">Loading\u2026</div>
       <div id="t0pager" class="t0pager"></div>
     </div>
     <div class="t0side card">
       <div class="k" style="margin-top:0">Selected <span id="t0count" class="muted">(0)</span></div>
       <div id="t0sel" class="t0sel muted small">None yet.</div>
       <div class="k">Recommended (auto-detected)</div>
       <div id="t0rec" class="t0rec muted small">Loading\u2026</div>
     </div>
   </div>
   <div style="margin-top:16px;display:flex;gap:10px;align-items:center">
     <button id="t0run">Run assessment</button>
     <button id="t0skip" class="ghost">Skip \u2014 recommended only</button>
     <span id="t0status" class="small muted"></span>
   </div>
   <div id="livelog" class="livelog" style="display:none"><div class="livelogtitle">Live analysis log</div><div id="logbody" class="logbody"></div></div>`;

 const sel=new Map();               // id -> {name,kind} (the user's chosen additional Tier-0)
 const recIds=new Set();            // ids that are auto-detected (pre-checked)
 let cats=[], curCat=null, curPage=1, curQ='';

 const refreshCount=()=>{ $('#t0count').textContent='('+sel.size+')';
   $('#t0run').textContent = sel.size?('Run assessment \u00b7 '+sel.size+' Tier-0'):'Run assessment';
   const s=$('#t0sel');
   s.innerHTML = sel.size? [...sel.entries()].slice(0,200).map(([id,v])=>`<div class="prow"><span class="pv">${_legendIcon(v.kind)} ${esc(v.name)}</span><button class="linkbtn" data-unsel="${esc(id)}">remove</button></div>`).join('') : 'None yet.';
   qa('button[data-unsel]',s).forEach(b=>b.onclick=()=>{sel.delete(b.dataset.unsel);refreshCount();paintList();}); };
 const toggle=(id,name,kind,on)=>{ if(on)sel.set(id,{name,kind}); else sel.delete(id); refreshCount(); };

 function paintList(){
   const el=$('#t0list'); if(!el)return;
   api(`/api/collect/${cid}/assets?category=${encodeURIComponent(curCat)}&q=${encodeURIComponent(curQ)}&page=${curPage}&per_page=20`).then(r=>{
     if(!r.items.length){el.innerHTML='<div class="muted small" style="padding:8px 2px">No assets match.</div>';$('#t0pager').innerHTML='';return;}
     el.innerHTML=r.items.map(a=>{const on=sel.has(a.id);const rec=recIds.has(a.id);
       return `<label class="t0row"><input type="checkbox" data-id="${esc(a.id)}" data-name="${esc(a.name)}" data-kind="${esc(a.kind)}" ${on?'checked':''}>
         <span class="t0nm">${_legendIcon(a.kind)} ${esc(a.name)}${a.tier0?' <span class="t0badge">Tier-0</span>':''}${rec&&!a.tier0?' <span class="t0badge">rec</span>':''}</span>
         <span class="t0dt muted">${esc(a.detail||'')}</span></label>`;}).join('');
     qa('input[type=checkbox]',el).forEach(cb=>cb.onchange=()=>toggle(cb.dataset.id,cb.dataset.name,cb.dataset.kind,cb.checked));
     const pg=$('#t0pager');
     pg.innerHTML=`<button class="linkbtn" id="t0prev" ${r.page<=1?'disabled':''}>\u2039 Prev</button>
       <span class="muted small">Page ${r.page} of ${r.pages} \u00b7 ${r.total} asset(s)</span>
       <button class="linkbtn" id="t0next" ${r.page>=r.pages?'disabled':''}>Next \u203a</button>`;
     const pv=$('#t0prev'),nx=$('#t0next'); if(pv)pv.onclick=()=>{if(curPage>1){curPage--;paintList();}}; if(nx)nx.onclick=()=>{if(curPage<r.pages){curPage++;paintList();}};
   }).catch(e=>{el.textContent='Error: '+e.message;});
 }

 try{
   const inv=await api(`/api/collect/${cid}/inventory`);
   cats=inv.categories||[];
   $('#t0cat').innerHTML=cats.map(c=>`<option value="${esc(c.kind)}">${esc(c.label)} (${c.count})</option>`).join('');
   curCat=cats.length?cats[0].kind:null;
   // Recommended: pre-check all, list on the right.
   (inv.recommended||[]).forEach(r=>{recIds.add(r.id);sel.set(r.id,{name:r.name,kind:r.kind});});
   const rec=$('#t0rec');
   rec.innerHTML=(inv.recommended||[]).length? `<div class="muted small" style="margin-bottom:6px">${inv.recommended.length} auto-detected \u00b7 all selected</div>`+
     inv.recommended.slice(0,300).map(r=>`<div class="prow" title="${esc(r.reason)}"><span class="pv">${_legendIcon(r.kind)} ${esc(r.name)}</span><span class="muted small" style="max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.reason)}</span></div>`).join('') : 'None auto-detected.';
   refreshCount();
   if(curCat)paintList();
 }catch(e){ $('#t0err').textContent='Could not load inventory: '+e.message; }

 $('#t0cat').onchange=e=>{curCat=e.target.value;curPage=1;paintList();};
 let qt=null; $('#t0q').oninput=e=>{clearTimeout(qt);curQ=e.target.value;qt=setTimeout(()=>{curPage=1;paintList();},220);};

 const runAssess=()=>{
   const ids=[...sel.keys()];
   const fd=new FormData();fd.append('collection_id',cid);fd.append('use_ai',useAi?'true':'false');fd.append('tier0_ids',JSON.stringify(ids));
   _driveAssessFromSelect(fd);
 };
 $('#t0run').onclick=runAssess;
 $('#t0skip').onclick=runAssess;   // skip = assess with the recommended set already selected
}

// Assessment driver used by the Tier-0 selection screen (renders log inline, then report).
async function _driveAssessFromSelect(fd){
 const st=$('#t0status'); if(st){st.innerHTML='<span class="spin"></span> analysing\u2026';}
 const run=$('#t0run'),skip=$('#t0skip'); if(run)run.disabled=true; if(skip)skip.disabled=true;
 const logEl=$('#livelog'), body=$('#logbody'); if(logEl)logEl.style.display='block'; if(body)body.innerHTML='';
 const appendLines=(lines)=>{ if(!body)return; for(const l of lines){ const row=document.createElement('div'); row.className='logrow';
   row.innerHTML=`<span class="logt">${new Date(l.t*1000).toLocaleTimeString()}</span><span class="logm"></span>`; row.querySelector('.logm').textContent=l.message; body.appendChild(row);} body.scrollTop=body.scrollHeight; };
 try{
   const start=await api('/api/assess/from-collection',{method:'POST',body:fd});
   const jobId=start.job_id; let seen=0,res=null;
   while(true){ const s2=await api(`/api/jobs/${jobId}?since=${seen}`); if(s2.log&&s2.log.length){appendLines(s2.log);seen=s2.log_count;} if(s2.done){res=s2;break;} await new Promise(r=>setTimeout(r,500)); }
   if(res.error||!res.scan_id){ if(st)st.textContent='Error: '+(res.error||'scan failed'); if(run)run.disabled=false; if(skip)skip.disabled=false; return; }
   if(st)st.textContent='';
   try{ renderScanResults(await api('/api/scans/'+res.scan_id),res.scan_id); }
   catch(e){ toast('Scan complete.'); setTimeout(()=>{location.hash='#/history';},400); }
 }catch(e){ if(st)st.textContent='Error: '+e.message; if(run)run.disabled=false; if(skip)skip.disabled=false; }
}

function recentScanCards(scans){
 if(!scans.length) return '<div class="muted small" style="padding:4px 0">No previous scans.</div>';
 return scans.map(s=>{
   const gc=gradeClass(s.grade);
   const files=esc((s.files||[]).join(', ')||'-');
   const crits=s.critical||0, highs=s.high||0, total=s.findings||0, apaths=s.attack_paths||0;
   const parts=[];
   if(crits) parts.push(`<span style="color:var(--crit)">${crits} crit</span>`);
   if(highs) parts.push(`<span style="color:var(--med)">${highs} high</span>`);
   parts.push(`${total} findings`);
   if(apaths) parts.push(`${apaths} attack paths`);
   return `<div style="display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border)">
     <span class="badge ${gc}" style="flex-shrink:0;font-size:14px;min-width:30px;text-align:center">${esc(s.grade||'?')}</span>
     <div style="flex:1;min-width:0">
       <div class="small" style="font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${files}</div>
       <div class="small muted" style="margin-top:2px">${fmtDate(s.created_at)} · ${parts.join(' · ')}</div>
     </div>
     <div style="display:flex;gap:6px;flex-shrink:0">
       <a class="btn ghost" style="padding:5px 11px;font-size:12px" href="/api/scans/${s.id}/report" target="_blank">Open full report ↗</a>
       <a class="btn ghost" style="padding:5px 11px;font-size:12px" href="/api/scans/${s.id}/report#roadmap" target="_blank">Action plan ↗</a>
     </div>
   </div>`;
 }).join('');
}

// ---- History ------------------------------------------------------------
let historyState={q:'',sort:'date',compareA:null,compareB:null};
function scanTable(scans){
 if(!scans.length)return '<div class="empty">No scans match.</div>';
 return `<div class="tablewrap"><table><thead><tr><th></th><th>When</th><th>Files</th><th>Grade</th><th>Crit</th><th>High</th><th>Findings</th><th>Atk Paths</th><th></th></tr></thead><tbody>
 ${scans.map(s=>`<tr>
   <td><input type="checkbox" class="chk cmpchk" data-id="${s.id}" ${historyState.compareA===s.id||historyState.compareB===s.id?'checked':''}></td>
   <td class="small muted">${fmtDate(s.created_at)}</td>
   <td class="small">${esc((s.files||[]).join(', ')||'\u2014')}</td>
   <td><span class="badge ${gradeClass(s.grade)}">${esc(s.grade||'?')}</span></td>
   <td>${s.critical}</td><td>${s.high}</td><td>${s.findings}</td><td>${s.attack_paths||0}</td>
   <td style="text-align:right;white-space:nowrap"><div class="rowacts">
     <a class="btn ghost" style="padding:5px 11px;font-size:12px" href="/api/scans/${s.id}/report" target="_blank">Open</a>
     <span class="sep"></span>
     <a class="rowlink" href="#/trace/${s.id}" title="AI reasoning trace">Trace</a>
     <a class="rowlink" href="/api/scans/${s.id}/collection" download="scan-${s.id}-collection.json" title="Raw collection JSON (AzureHound format)">JSON</a>
     <a class="rowlink" href="/api/scans/${s.id}/export.csv" title="Findings CSV">CSV</a>
     <button class="rowdel" data-del="${s.id}" title="Delete scan" aria-label="Delete scan">&times;</button>
   </div></td>
 </tr>`).join('')}</tbody></table></div>`;
}
function applyHistoryFilter(scans){
 let out=scans;
 if(historyState.q){const q=historyState.q.toLowerCase();out=out.filter(s=>(s.files||[]).join(' ').toLowerCase().includes(q)||String(s.grade||'').toLowerCase().includes(q));}
 const sorters={date:(a,b)=>(b.created_at||0)-(a.created_at||0), grade:(a,b)=>(a.grade||'Z').localeCompare(b.grade||'Z'), critical:(a,b)=>b.critical-a.critical};
 return [...out].sort(sorters[historyState.sort]||sorters.date);
}
async function viewHistory(){
 const app=$('#app');app.innerHTML='<h1>History</h1><p class="sub">Previous scans, stored locally on this host. Select two to compare.</p>'+
   '<div id="running-section"></div>'+
   '<div class="toolbar"><input type="text" class="search" id="hq" placeholder="Search by filename or grade\u2026" value="'+esc(historyState.q)+'">'+
   '<select id="hsort" class="hsort"><option value="date">Newest first</option><option value="grade">By grade</option><option value="critical">By critical count</option></select>'+
   '<button class="btn ghost" id="cmpBtn" style="padding:8px 14px;font-size:12.5px" disabled>Compare selected</button></div>'+
   '<div class="card" id="hist">Loading\u2026</div><div id="cmpresult"></div>';
 $('#hsort').value=historyState.sort;
 let scans=[];try{scans=await api('/api/scans');}catch(e){}
 const paint=()=>{ $('#hist').innerHTML = scans.length?scanTable(applyHistoryFilter(scans)):'<div class="empty">No scans yet. <a href="#/scan">Run a scan \u2192</a></div>';
   qa('[data-del]',app).forEach(b=>b.onclick=()=>delBtn(b,()=>{historyState.compareA=historyState.compareB=null;viewHistory();}));
   qa('.cmpchk',app).forEach(cb=>cb.onchange=()=>{
     const id=cb.dataset.id;
     if(cb.checked){ if(!historyState.compareA) historyState.compareA=id; else if(!historyState.compareB && id!==historyState.compareA) historyState.compareB=id; else {cb.checked=false;toast('Only two scans can be compared at once.');} }
     else { if(historyState.compareA===id) historyState.compareA=null; if(historyState.compareB===id) historyState.compareB=null; }
     $('#cmpBtn').disabled = !(historyState.compareA && historyState.compareB);
   });
   $('#cmpBtn').disabled = !(historyState.compareA && historyState.compareB);
 };
 paint();
 async function paintRunning(){
   const sec=$('#running-section'); if(!sec) return;
   let running=[];try{running=await api('/api/jobs');}catch(e){}
   if(!running.length){sec.innerHTML='';return;}
   sec.innerHTML=`<div class="card" style="margin-bottom:12px">
     <div style="font-size:13px;font-weight:700;margin-bottom:10px;display:flex;align-items:center;gap:8px"><span class="spin"></span>Active scans</div>
     ${running.map(j=>`<div style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid var(--border)">
       <div style="flex:1;min-width:0">
         <div class="small" style="font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc((j.files||[]).join(', ')||'Scan in progress\u2026')}</div>
         <div class="small muted" style="margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${j.last_message?esc(j.last_message):'Starting\u2026'}</div>
       </div>
       <div style="display:flex;gap:6px;flex-shrink:0">
         <a class="btn ghost" style="padding:5px 11px;font-size:12px" href="#/job/${j.id}">View log</a>
         <button class="danger" data-cancel="${j.id}">Cancel</button>
       </div>
     </div>`).join('')}
   </div>`;
   qa('[data-cancel]',sec).forEach(b=>b.onclick=async()=>{b.disabled=true;try{await api('/api/jobs/'+b.dataset.cancel+'/cancel',{method:'POST'});}catch(e){}await paintRunning();paint();});
 }
 await paintRunning();
 const _poll=setInterval(async()=>{if(!$('#running-section')){clearInterval(_poll);return;}await paintRunning();},3000);
 $('#hq').oninput=e=>{historyState.q=e.target.value;paint();};
 $('#hsort').onchange=e=>{historyState.sort=e.target.value;paint();};
 $('#cmpBtn').onclick=async()=>{
   try{const c=await api(`/api/scans/${historyState.compareA}/compare/${historyState.compareB}`);
     $('#cmpresult').innerHTML=renderComparison(c);
   }catch(e){toast('Comparison failed: '+e.message);}
 };
}
async function viewJob(jobId){
 if(!jobId){location.hash='#/history';return;}
 const app=$('#app');
 app.innerHTML=`<h1>Scan log</h1><div class="card">
   <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
     <span class="spin" id="jobspin"></span><span id="jobstatus" class="small muted">Running\u2026</span>
     <span id="tracedl" class="small" style="margin-left:8px"></span>
     <button id="canceljob" class="danger" style="margin-left:auto">\u25a0 Cancel scan</button>
   </div>
   <div class="livelog" style="display:block"><div class="livelogtitle">Live analysis log</div><div id="logbody" class="logbody"></div></div>
   <div class="livelog" style="display:block;margin-top:12px">
     <div class="livelogtitle" style="display:flex;align-items:center;gap:8px">\u2726 AI reasoning \u00b7 verbose trace
       <label class="small muted" style="margin-left:auto;font-weight:400;cursor:pointer"><input type="checkbox" id="traceauto" checked> auto-scroll</label></div>
     <pre id="tracebody" class="logbody" style="white-space:pre-wrap;font-family:var(--mono,monospace);font-size:11.5px;line-height:1.45;max-height:460px"></pre>
   </div>
 </div>`;
 const appendLines=lines=>{const body=$('#logbody');if(!body)return;for(const l of lines){const row=document.createElement('div');row.className='logrow';row.innerHTML=`<span class="logt">${new Date(l.t*1000).toLocaleTimeString()}</span><span class="logm"></span>`;row.querySelector('.logm').textContent=l.message;body.appendChild(row);}body.scrollTop=body.scrollHeight;};
 const appendTrace=txt=>{const tb=$('#tracebody');if(!tb||!txt)return;tb.appendChild(document.createTextNode(txt));const auto=$('#traceauto');if(!auto||auto.checked)tb.scrollTop=tb.scrollHeight;};
 $('#canceljob').onclick=async()=>{$('#canceljob').disabled=true;try{await api('/api/jobs/'+jobId+'/cancel',{method:'POST'});}catch(e){}};
 let seen=0, tOff=0;
 while(true){
   if(!$('#logbody'))break;
   // stream the verbose AI trace by byte offset (independent of the progress log)
   try{const tr=await api(`/api/jobs/${jobId}/trace?offset=${tOff}`);if(tr&&tr.exists){appendTrace(tr.text);tOff=tr.offset;}}catch(e){}
   let st2;try{st2=await api(`/api/jobs/${jobId}?since=${seen}`);}catch(e){break;}
   if(st2.log&&st2.log.length){appendLines(st2.log);seen=st2.log_count;}
   if(st2.done){
     try{const tr=await api(`/api/jobs/${jobId}/trace?offset=${tOff}`);if(tr&&tr.exists){appendTrace(tr.text);tOff=tr.offset;}}catch(e){}
     const spin=$('#jobspin'),status=$('#jobstatus'),cancelBtn=$('#canceljob');
     if(spin)spin.style.display='none';if(cancelBtn)cancelBtn.style.display='none';
     if(st2.error){if(status)status.textContent='\u26a0 '+st2.error;}
     else if(st2.scan_id){if(status)status.innerHTML='\u2713 Complete \u2014 <a href="#/history">View in history</a>';
       const dl=$('#tracedl');if(dl)dl.innerHTML=`\u2726 <a href="/api/scans/${st2.scan_id}/trace" download="scan-${st2.scan_id}-ai-trace.log">Download AI trace (.log)</a> \u00b7 <a href="/api/scans/${st2.scan_id}/trace?format=jsonl" download="scan-${st2.scan_id}-ai-trace.jsonl">.jsonl</a>`;}
     break;
   }
   await new Promise(r=>setTimeout(r,600));
 }
}
function renderComparison(c){
 const delta=c.score_delta; const deltaCol=delta>0?'var(--ok)':delta<0?'var(--crit)':'var(--tx3)';
 const deltaStr=delta>0?'+'+delta:String(delta);
 const sevCol={Critical:'var(--crit)',High:'var(--high)',Medium:'var(--med)',Low:'var(--low)',Info:'var(--tx3)'};
 const list=(items,empty)=>items.length?items.map(i=>`<div class="cmprow"><span class="sevpill" style="background:${sevCol[i.severity]||'#888'}22;color:${sevCol[i.severity]||'#888'}">${esc(i.severity)}</span> ${esc(i.title)}</div>`).join(''):`<div class="muted small">${empty}</div>`;
 return `<div class="card" style="margin-top:16px">
   <h1 style="font-size:15px;margin:0 0 4px">Comparison</h1>
   <p class="sub" style="margin:0 0 14px">${fmtDate(c.a.created_at)} (${esc(c.a.grade)}, ${c.a.score}) \u2192 ${fmtDate(c.b.created_at)} (${esc(c.b.grade)}, ${c.b.score}) \u00B7 <b style="color:${deltaCol}">${deltaStr} pts</b></p>
   <div class="two">
     <div><div class="muted small" style="margin-bottom:8px">\u2705 Resolved (${c.resolved.length})</div>${list(c.resolved,'Nothing resolved between these scans.')}</div>
     <div><div class="muted small" style="margin-bottom:8px">\u26A0\uFE0F New (${c.new.length})</div>${list(c.new,'No new findings.')}</div>
   </div>
   <div class="small muted" style="margin-top:10px">${c.persisting_count} finding(s) present in both scans, unchanged.</div>
 </div>`;
}

// ---- Settings -----------------------------------------------------------
async function viewSettings(){
 const app=$('#app');let s={};
 try{s=await api('/api/settings');}catch(e){}
 app.innerHTML=`<h1>Settings</h1><p class="sub">Configure AI integration. Settings persist on this host.</p>
 <div class="card" style="max-width:620px">
   <label class="fld">Anthropic API key</label>
   <input type="password" id="key" placeholder="${s.api_key_source==='env'?'\u25CF\u25CF\u25CF\u25CF\u25CF\u25CF loaded from .env':s.api_key_set?'\u25CF\u25CF\u25CF\u25CF\u25CF\u25CF set \u2014 enter a new key to replace':'sk-ant-...'}" autocomplete="off" ${s.api_key_source==='env'?'disabled':''}>
   <div class="hint">${s.api_key_source==='env'?'Key is loaded from the <code>.env</code> file \u2014 no need to enter it here. Remove it from <code>.env</code> to override via this form.':'Held in memory for this server session only. Cleared on restart. Set <code>ANTHROPIC_API_KEY</code> in <code>.env</code> to persist across restarts.'}</div>
   <div class="row" style="margin-top:10px">${s.api_key_source!=='env'?'<button id="savekey">Save key</button>':''}
     ${s.api_key_source==='settings'?'<button class="ghost" id="clearkey">Clear key</button>':''}
     <span class="small muted" id="keyst">${s.api_key_source==='env'?'\u2713 Key active (from .env)':s.api_key_set?'A key is currently set.':'No key set.'}</span></div>
   <label class="fld" style="margin-top:22px">Minimum severity shown in CLI/exports</label>
   <select id="sev">${['Info','Low','Medium','High','Critical'].map(x=>`<option ${s.min_severity===x?'selected':''}>${x}</option>`).join('')}</select>
   <label class="fld" style="margin-top:22px">Sonnet model <span class="muted small">(Phase 2 \u2014 17 parallel specialist analysts)</span></label>
   <input type="text" id="sonnetmodel" value="${esc(s.sonnet_model||'claude-sonnet-5')}" placeholder="claude-sonnet-5">
   <label class="fld">Opus model <span class="muted small">(Phase 2b+3 \u2014 cross-domain synthesizer &amp; attack-chain correlator)</span></label>
   <input type="text" id="opusmodel" value="${esc(s.opus_model||'claude-opus-5')}" placeholder="claude-opus-5">
   <label class="fld">Skeptic model <span class="muted small">(Phase 4 \u2014 adversarial review of Critical/High findings)</span></label>
   <input type="text" id="haikumodel" value="${esc(s.haiku_model||'claude-sonnet-5')}" placeholder="claude-sonnet-5">
   <div class="row" style="margin-top:10px"><button class="ghost" id="testconn">Test AI connection</button><span class="small muted" id="connst"></span></div>
   <div style="margin-top:18px"><button id="save">Save settings</button> <span class="small muted" id="st"></span></div>
 </div>
 <div class="card" style="max-width:620px;margin-top:16px">
   <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
     <span style="font-size:15px;font-weight:700">Account &amp; sign-in</span>
     <span style="font-size:12px">${s.auth_must_change?'<span style="color:var(--med)">● using default password</span>':'● password set'}</span>
   </div>
   <p class="hint" style="margin-bottom:14px">Change the sign-in credentials for this PostureHound instance. The password is stored hashed (PBKDF2) on this host; sessions use a signed JWT. ${s.auth_must_change?'<b>You are still using the default password - change it now.</b>':''}</p>
   <label class="fld">Username</label>
   <input type="text" id="acctuser" value="${esc(s.auth_username||'admin')}" autocomplete="username">
   <label class="fld">Current password</label>
   <input type="password" id="acctcur" placeholder="current password" autocomplete="current-password">
   <label class="fld">New password <span class="muted small">(min 8 characters)</span></label>
   <input type="password" id="acctnew" placeholder="new password" autocomplete="new-password">
   <div class="row" style="margin-top:10px"><button id="acctsave">Update credentials</button><span class="small muted" id="acctst"></span></div>
 </div>
 <div class="card" style="max-width:620px;margin-top:16px">
   <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
     <span style="font-size:15px;font-weight:700">Azure live collection</span>
     <span style="font-size:11px;padding:2px 9px;border-radius:999px;background:rgba(94,124,175,.18);color:#7d93aa;font-weight:600;letter-spacing:.04em">RESOURCE GRAPH + MS GRAPH</span>
     <span style="font-size:12px">${s.arg_configured?'● configured':'○ not configured'}</span>
   </div>
   <p class="hint" style="margin-bottom:14px">A read-only Reader service principal lets PostureHound also assess network exposure, databases and identity config (Conditional Access / MFA) that AzureHound cannot see. Grant it <b>Reader</b> (ARM) and <b>Policy.Read.All</b> (Microsoft Graph, admin-consented). The secret is stored on this host; you can instead set PH_ARG_TENANT_ID / PH_ARG_CLIENT_ID / PH_ARG_CLIENT_SECRET.</p>
   <label class="fld">Tenant ID</label>
   <input type="text" id="argtenant" value="${esc(s.arg_tenant_id||'')}" placeholder="00000000-0000-0000-0000-000000000000" autocomplete="off">
   <label class="fld">Client ID (application ID)</label>
   <input type="text" id="argclient" value="${esc(s.arg_client_id||'')}" placeholder="00000000-0000-0000-0000-000000000000" autocomplete="off">
   <label class="fld">Client secret</label>
   <input type="password" id="argsecret" placeholder="${s.arg_secret_set?'●●●●●● set - enter a new secret to replace':'client secret'}" autocomplete="off">
   <div class="row" style="margin-top:10px">
     <button id="argsave">Save service principal</button>
     <button class="ghost" id="argtest">Test connection</button>
     ${s.arg_configured?'<button class="ghost" id="argclear">Clear</button>':''}
     <span class="small muted" id="argst"></span>
   </div>
 </div>
 <div class="card" style="max-width:620px;margin-top:16px">
   <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
     <span style="font-size:15px;font-weight:700">Azure DevOps integration</span>
     <span style="font-size:11px;padding:2px 9px;border-radius:999px;background:rgba(94,124,175,.18);color:#7d93aa;font-weight:600;letter-spacing:.04em">WORK ITEMS</span>
     <span style="font-size:12px">${s.ado_configured?'● configured':(s.ado_enabled?'○ enabled, incomplete':'○ off')}</span>
   </div>
   <p class="hint" style="margin-bottom:14px">Adds a <b>Create work item</b> button to every finding in the report, so you can raise an Azure DevOps ${esc(s.ado_work_item_type||'Feature')} (optionally under a parent Epic) and assign it. The PAT is read <b>only</b> from the <code>PH_ADO_PAT</code> environment variable (Work Items: Read &amp; Write scope) and is never stored on disk. Buttons appear only when this is enabled and configured.</p>
   <label class="fld"><input type="checkbox" id="adoen" ${s.ado_enabled?'checked':''}> Enable Azure DevOps integration</label>
   <label class="fld">Organization URL <span class="muted small">(ADO path)</span></label>
   <input type="text" id="adourl" value="${esc(s.ado_org_url||'')}" placeholder="https://dev.azure.com/your-org" autocomplete="off">
   <label class="fld">Project</label>
   <input type="text" id="adoproj" value="${esc(s.ado_project||'')}" placeholder="Security" autocomplete="off">
   <label class="fld">Work item type</label>
   <input type="text" id="adotype" value="${esc(s.ado_work_item_type||'Feature')}" placeholder="Feature" autocomplete="off">
   <label class="fld">Area path <span class="muted small">(optional)</span></label>
   <input type="text" id="adoarea" value="${esc(s.ado_area_path||'')}" placeholder="Security\\Cloud" autocomplete="off">
   <label class="fld">Default parent Epic id <span class="muted small">(optional, numeric)</span></label>
   <input type="text" id="adoepic" value="${esc(s.ado_default_parent_epic||'')}" placeholder="e.g. 1042" autocomplete="off">
   <label class="fld">Tags <span class="muted small">(comma-separated; PostureHound + severity are added automatically)</span></label>
   <input type="text" id="adotags" value="${esc(s.ado_tags||'')}" placeholder="cloud, azure, posture" autocomplete="off">
   <label class="fld">Default assignee <span class="muted small">(email / UPN)</span></label>
   <input type="text" id="adoassignee" value="${esc(s.ado_default_assignee||'')}" placeholder="security-owner@contoso.com" autocomplete="off">
   <div class="hint" style="margin-top:10px">PAT: ${s.ado_pat_present?'✅ PH_ADO_PAT is set':'⚠ PH_ADO_PAT not set - export it in the environment to create work items'}</div>
   <div class="row" style="margin-top:10px">
     <button id="adosave">Save</button>
     <button class="ghost" id="adotest">Test connection</button>
     <span class="small muted" id="adost"></span>
   </div>
 </div>`;
 // Every handler below must be attached defensively. This block renders different
 // controls depending on where the API key comes from - with the key supplied via
 // .env / the environment, the "Save key" and "Clear key" buttons are NOT rendered.
 // An unguarded `$('#savekey').onclick = …` therefore threw
 // "Cannot set properties of null", which aborted the rest of the function and left
 // #testconn present but with NO click handler - i.e. "Test AI connection" silently
 // did nothing for exactly the users who had a working key.
 const _on=(sel,fn)=>{const el=$(sel);if(el)el.onclick=fn;return !!el;};
 _on('#save',async()=>{const fd=new FormData();fd.append('min_severity',$('#sev').value);
   fd.append('sonnet_model',$('#sonnetmodel').value.trim());fd.append('opus_model',$('#opusmodel').value.trim());fd.append('haiku_model',$('#haikumodel').value.trim());
   try{await api('/api/settings',{method:'POST',body:fd});$('#st').textContent='Saved.';toast('Settings saved.');}catch(e){$('#st').textContent='Error: '+e.message;}});
 _on('#savekey',async()=>{const k=$('#key').value.trim();if(!k){toast('Enter a key.');return;}
   const fd=new FormData();fd.append('anthropic_key',k);
   try{await api('/api/settings',{method:'POST',body:fd});toast('Key saved (in memory).');refreshKeyPill();viewSettings();}catch(e){toast('Error: '+e.message);}});
 _on('#clearkey',async()=>{const fd=new FormData();fd.append('clear_key','true');
   try{await api('/api/settings',{method:'POST',body:fd});toast('Key cleared.');refreshKeyPill();viewSettings();}catch(e){toast('Error');}});
 _on('#acctsave',async()=>{
   const cur=$('#acctcur').value,nw=$('#acctnew').value,un=$('#acctuser').value.trim();
   if(!cur){$('#acctst').textContent='Enter your current password.';return;}
   if((nw||'').length<8){$('#acctst').textContent='New password must be at least 8 characters.';return;}
   const fd=new URLSearchParams({current_password:cur,new_password:nw,new_username:un});
   try{const r=await fetch('/api/auth/password',{method:'POST',body:fd});
     if(!r.ok){let d={};try{d=await r.json();}catch(_){}$('#acctst').textContent=d.detail||('HTTP '+r.status);return;}
     toast('Credentials updated.');const bn=$('#pwbanner');if(bn)bn.hidden=true;viewSettings();
   }catch(e){$('#acctst').textContent=e.message;}});
 _on('#testconn',async()=>{
   const btn=$('#testconn'); btn.disabled=true; $('#connst').innerHTML='<span class="spin"></span> testing\u2026';
   const fd=new FormData();
   if($('#key').value.trim())fd.append('anthropic_key',$('#key').value.trim());
   fd.append('sonnet_model',$('#sonnetmodel').value.trim()); fd.append('opus_model',$('#opusmodel').value.trim()); fd.append('haiku_model',$('#haikumodel').value.trim());
   try{
     const r=await api('/api/settings/test-connection',{method:'POST',body:fd});
     const parts=Object.entries(r).map(([role,res])=>`${res.ok?'\u2705':'\u274C'} ${role} (${esc(res.model)})${res.ok?'':': '+esc(res.error||'failed')}`);
     $('#connst').innerHTML=parts.join(' &nbsp; ');
   }catch(e){$('#connst').textContent='Error: '+e.message;}
   btn.disabled=false;
 });
 // ---- Azure live collection (Resource Graph / MS Graph) service principal ----
 _on('#argsave',async()=>{
   const fd=new FormData();
   fd.append('arg_tenant_id',$('#argtenant').value.trim());
   fd.append('arg_client_id',$('#argclient').value.trim());
   const sec=$('#argsecret').value.trim(); if(sec)fd.append('arg_client_secret',sec);
   try{await api('/api/settings',{method:'POST',body:fd});toast('Service principal saved.');viewSettings();}
   catch(e){$('#argst').textContent='Error: '+e.message;}
 });
 _on('#argclear',async()=>{
   const fd=new FormData();fd.append('arg_clear','true');
   try{await api('/api/settings',{method:'POST',body:fd});toast('Service principal cleared.');viewSettings();}
   catch(e){toast('Error: '+e.message);}
 });
 _on('#argtest',async()=>{
   const btn=$('#argtest');btn.disabled=true;$('#argst').innerHTML='<span class="spin"></span> testing…';
   const fd=new FormData();
   const t=$('#argtenant').value.trim(),c=$('#argclient').value.trim(),sec=$('#argsecret').value.trim();
   if(t&&c&&sec){fd.append('arg_tenant_id',t);fd.append('arg_client_id',c);fd.append('arg_client_secret',sec);}
   try{
     const r=await api('/api/settings/test-arg-connection',{method:'POST',body:fd});
     const rg=r.resource_graph||{ok:r.ok,message:r.message};
     const mg=r.microsoft_graph||{ok:false,message:'not checked'};
     $('#argst').innerHTML=
       (rg.ok?'✅':'❌')+' Resource Graph (Reader): '+esc(rg.message||'')+'<br>'+
       (mg.ok?'✅':'❌')+' Microsoft Graph (Policy.Read.All): '+esc(mg.message||'');
   }catch(e){$('#argst').textContent='Error: '+e.message;}
   btn.disabled=false;
 });
 // ---- Azure DevOps work-item integration ----
 _on('#adosave',async()=>{
   const fd=new FormData();
   fd.append('ado_enabled',$('#adoen').checked?'true':'false');
   fd.append('ado_org_url',$('#adourl').value.trim());
   fd.append('ado_project',$('#adoproj').value.trim());
   fd.append('ado_work_item_type',$('#adotype').value.trim()||'Feature');
   fd.append('ado_area_path',$('#adoarea').value.trim());
   fd.append('ado_default_parent_epic',$('#adoepic').value.trim());
   fd.append('ado_tags',$('#adotags').value.trim());
   fd.append('ado_default_assignee',$('#adoassignee').value.trim());
   try{await api('/api/settings',{method:'POST',body:fd});toast('Azure DevOps settings saved.');viewSettings();}
   catch(e){$('#adost').textContent='Error: '+e.message;}
 });
 _on('#adotest',async()=>{
   const btn=$('#adotest');btn.disabled=true;$('#adost').innerHTML='<span class="spin"></span> testing…';
   // save first so the test uses the on-screen values
   const fd=new FormData();
   fd.append('ado_enabled',$('#adoen').checked?'true':'false');
   fd.append('ado_org_url',$('#adourl').value.trim());fd.append('ado_project',$('#adoproj').value.trim());
   fd.append('ado_work_item_type',$('#adotype').value.trim()||'Feature');fd.append('ado_area_path',$('#adoarea').value.trim());
   fd.append('ado_default_parent_epic',$('#adoepic').value.trim());fd.append('ado_tags',$('#adotags').value.trim());
   fd.append('ado_default_assignee',$('#adoassignee').value.trim());
   try{await api('/api/settings',{method:'POST',body:fd});
     const r=await api('/api/integrations/ado/test',{method:'POST'});
     $('#adost').innerHTML='✅ Connected to project '+esc(r.project||'');
   }catch(e){$('#adost').innerHTML='❌ '+esc(e.message);}
   btn.disabled=false;
 });
}

// ---- Rule Library ------------------------------------------------------
let _RULES=[], _RULESTATE={q:'',cat:'',sev:'',fw:'',type:'',engine:'',scan:''}, _RULESTATUS=null;
function _sevRank(s){return ['Critical','High','Medium','Low','Info'].indexOf(s);}
async function viewRules(){
  const app=$('#app');
  app.innerHTML='<h1>Rule Library</h1><p class="sub">Every deterministic detection rule PostureHound ships - offensive/blast-radius paths and CIS-benchmark best practices. Filter and inspect each rule; pick a scan to see whether it fired, was silent, or was not assessed.</p><div class="card" id="rulewrap">Loading…</div>';
  if(!_RULES.length){try{const r=await api('/api/rules');_RULES=r.rules||[];}catch(e){$('#rulewrap').textContent='Error: '+e.message;return;}}
  let scans=[];try{scans=await api('/api/scans');}catch(e){}
  const cats=[...new Set(_RULES.map(r=>r.category))].sort();
  const engines=[...new Set(_RULES.map(r=>r.engine))].sort();
  $('#rulewrap').innerHTML=`
    <div class="rbar">
      <input class="search" id="rq" placeholder="Search id, title, description…" value="${esc(_RULESTATE.q)}">
      <select id="rcat"><option value="">All categories</option>${cats.map(c=>`<option value="${esc(c)}">${esc(c)}</option>`).join('')}</select>
      <select id="rsev"><option value="">All severities</option>${['Critical','High','Medium','Low','Info'].map(s=>`<option>${s}</option>`).join('')}</select>
      <select id="rfw"><option value="">All frameworks</option><option value="CIS Azure">Has CIS</option><option value="MITRE ATT&CK">Has MITRE</option><option value="Azure Threat Matrix">Has ATRM</option></select>
      <select id="rtype"><option value="">All types</option><option value="bp">Best practice</option><option value="off">Offensive / blast-radius</option></select>
      <select id="reng"><option value="">All engines</option>${engines.map(e=>`<option value="${esc(e)}">${esc(e)}</option>`).join('')}</select>
      <select id="rscan"><option value="">- overlay a scan's results -</option>${scans.map(s=>`<option value="${esc(s.id)}">${esc(fmtDate(s.created_at))} · ${esc(s.grade)} (${s.score})</option>`).join('')}</select>
    </div>
    <div class="rmeta" id="rmeta"></div>
    <div id="rtable"></div>`;
  const _set=(id,k)=>{const el=$('#'+id);if(el)el.onchange=el.oninput=()=>{_RULESTATE[k]=el.value;_paintRules();};};
  _set('rq','q');_set('rcat','cat');_set('rsev','sev');_set('rfw','fw');_set('rtype','type');_set('reng','engine');
  $('#rscan').onchange=async()=>{_RULESTATE.scan=$('#rscan').value;_RULESTATUS=null;
    if(_RULESTATE.scan){try{_RULESTATUS=await api('/api/scans/'+_RULESTATE.scan+'/rules');}catch(e){}}
    _paintRules();};
  if(_RULESTATE.scan){$('#rscan').value=_RULESTATE.scan;try{_RULESTATUS=await api('/api/scans/'+_RULESTATE.scan+'/rules');}catch(e){}}
  _paintRules();
}
function _ruleStatus(id){
  if(!_RULESTATUS)return null;
  if((_RULESTATUS.fired||{})[id]!=null)return {k:'fired',n:_RULESTATUS.fired[id]};
  if((_RULESTATUS.not_assessed||[]).includes(id))return {k:'na'};
  return {k:'silent'};
}
function _paintRules(){
  const st=_RULESTATE, q=st.q.toLowerCase();
  let rows=_RULES.filter(r=>{
    if(st.cat&&r.category!==st.cat)return false;
    if(st.sev&&r.severity!==st.sev)return false;
    if(st.engine&&r.engine!==st.engine)return false;
    if(st.fw&&!(r.frameworks||{})[st.fw])return false;
    if(st.type==='bp'&&!r.best_practice)return false;
    if(st.type==='off'&&r.best_practice)return false;
    if(q&&!((r.id+' '+r.title+' '+r.description+' '+Object.values(r.frameworks||{}).join(' ')).toLowerCase().includes(q)))return false;
    return true;
  });
  rows.sort((a,b)=>(_sevRank(a.severity)-_sevRank(b.severity))||a.id.localeCompare(b.id));
  const showStatus=!!_RULESTATUS;
  $('#rmeta').innerHTML=`${rows.length} of ${_RULES.length} rules${showStatus?' · '+(rows.filter(r=>{const s=_ruleStatus(r.id);return s&&s.k==='fired';}).length)+' fired on the selected scan':''}`;
  const badge=r=>{const s=_ruleStatus(r.id);if(!s)return '';
    if(s.k==='fired')return `<span class="rst rst-fired">fired ×${s.n}</span>`;
    if(s.k==='na')return `<span class="rst rst-na">not assessed</span>`;
    return `<span class="rst rst-silent">silent</span>`;};
  const fw=r=>{const f=r.frameworks||{};return [f['CIS Azure']?`<span class="fwpill cis">CIS ${esc(f['CIS Azure'])}</span>`:'',f['MITRE ATT&CK']?`<span class="fwpill mit">${esc(f['MITRE ATT&CK'])}</span>`:'',f['Azure Threat Matrix']?`<span class="fwpill atrm">${esc(f['Azure Threat Matrix'])}</span>`:''].join('');};
  $('#rtable').innerHTML=`<table class="rtbl"><thead><tr><th>ID</th><th>Rule</th><th>Sev</th><th>Category</th><th>Frameworks</th>${showStatus?'<th>On scan</th>':''}</tr></thead><tbody>${rows.map(r=>`
    <tr class="rrow" data-id="${esc(r.id)}">
      <td class="mono">${esc(r.id)}${r.best_practice?' <span class="bpdot" title="best practice / hardening">✦</span>':''}</td>
      <td>${esc(r.title)}</td>
      <td><span class="sevtag" style="background:${_sevColor(r.severity)}">${esc(r.severity)}</span></td>
      <td class="small">${esc(r.category)}</td>
      <td>${fw(r)}</td>
      ${showStatus?`<td>${badge(r)}</td>`:''}
    </tr>
    <tr class="rdetail" data-for="${esc(r.id)}" hidden><td colspan="${showStatus?6:5}">${_ruleDetail(r)}</td></tr>`).join('')||`<tr><td colspan="6" class="muted">No rules match.</td></tr>`}</tbody></table>`;
  qa('.rrow',$('#rtable')).forEach(tr=>tr.onclick=()=>{const d=$('#rtable').querySelector(`.rdetail[data-for="${CSS.escape(tr.dataset.id)}"]`);if(d)d.hidden=!d.hidden;});
}
function _sevColor(s){return {Critical:'#c0392b',High:'#e67e22',Medium:'#e8c257',Low:'#5a7a9a',Info:'#6b7280'}[s]||'#6b7280';}
function _ruleDetail(r){
  const k=r.knowledge||{};
  const steps=(k.steps||[]).map(s=>`<li>${esc(s)}</li>`).join('');
  const fwrows=Object.entries(r.frameworks||{}).map(([a,b])=>`<span class="fwpill">${esc(a)}: ${esc(b)}</span>`).join('')||'<span class="muted small">-</span>';
  return `<div class="rdet">
    <div class="muted small" style="margin-bottom:6px">${esc(r.engine)} · data: ${esc((r.data_source||[]).join(', ')||'-')}</div>
    <p>${esc(k.summary||r.description||'')}</p>
    ${k.why?`<div class="rk">Why it matters</div><p>${esc(k.why)}</p>`:''}
    ${k.scenario?`<div class="rk">Attack scenario</div><p>${esc(k.scenario)}</p>`:''}
    <div class="rk">Remediation</div><p>${esc(r.remediation||'')}</p>
    ${steps?`<ol class="steps">${steps}</ol>`:''}
    ${k.detection?`<div class="rk">Detection</div><p class="small">${esc(k.detection)}</p>`:''}
    <div class="rk">Frameworks</div><div>${fwrows}</div>
  </div>`;
}

// ---- AI trace viewer ----------------------------------------------------
async function viewTraces(){
 const app=$('#app');
 app.innerHTML='<h1>AI Traces</h1><p class="sub">The verbose reasoning transcript for each scan - how every specialist thought, what it kept or rejected, and why. Viewable here; download is an extra option. Traces exist for scans run with tracing enabled.</p><div class="card" id="tlist">Loading…</div>';
 let scans=[];try{scans=await api('/api/scans');}catch(e){}
 if(!scans.length){$('#tlist').innerHTML='<div class="empty">No scans yet. <a href="#/scan">Run a scan →</a></div>';return;}
 $('#tlist').innerHTML=`<table><thead><tr><th>When</th><th>Files</th><th>Grade</th><th>Findings</th><th></th></tr></thead><tbody>
   ${scans.map(s=>`<tr>
     <td class="small muted">${fmtDate(s.created_at)}</td>
     <td class="small">${esc((s.files||[]).join(', ')||'-')}</td>
     <td><span class="badge ${gradeClass(s.grade)}">${esc(s.grade||'?')}</span></td>
     <td>${s.findings}</td>
     <td style="text-align:right;white-space:nowrap">
       <a class="btn" style="padding:6px 14px;font-size:12.5px" href="#/trace/${s.id}">✦ View AI reasoning</a></td>
   </tr>`).join('')}</tbody></table>`;
}

async function viewTrace(scanId){
 setNav('traces');
 const app=$('#app');
 app.innerHTML=`<div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
     <h1 style="margin:0">✦ AI reasoning trace</h1>
     <span class="small muted">scan ${esc(scanId||'')}</span>
     <span style="margin-left:auto;display:flex;gap:8px;align-items:center">
       <input type="text" id="tfilter" class="search" placeholder="Filter lines…" style="width:200px">
       <a class="btn ghost" style="padding:7px 13px;font-size:12.5px" href="/api/scans/${esc(scanId)}/trace" download="scan-${esc(scanId)}-ai-trace.log">Download .log</a>
       <a class="btn ghost" style="padding:7px 13px;font-size:12.5px" href="/api/scans/${esc(scanId)}/trace?format=jsonl" download="scan-${esc(scanId)}-ai-trace.jsonl">.jsonl</a>
       <a class="btn ghost" style="padding:7px 13px;font-size:12.5px" href="#/traces">← All traces</a>
     </span></div>
   <p class="sub" style="margin:6px 0 14px">Local artifact - contains tenant specifics, never part of the shareable report.</p>
   <div class="card" style="padding:0"><pre id="tracebody" class="logbody" style="white-space:pre-wrap;font-family:var(--mono,monospace);font-size:11.5px;line-height:1.5;max-height:72vh;margin:0;padding:16px;overflow:auto"></pre></div>`;
 let text='';
 try{
   const r=await fetch('/api/scans/'+encodeURIComponent(scanId)+'/trace');
   if(r.status===404){text='__NONE__';} else if(!r.ok){text='Error loading trace: HTTP '+r.status;} else {text=await r.text();}
 }catch(e){text='Error loading trace: '+e.message;}
 const tb=$('#tracebody');if(!tb)return;
 if(text==='__NONE__'){tb.textContent='No AI trace was recorded for this scan. Traces are written for scans run after the trace feature was enabled; re-run the scan to capture one.';tb.style.color='var(--tx3)';return;}
 const ALL=text, NL=String.fromCharCode(10);
 const render=q=>{ if(!q){tb.textContent=ALL;return;} const ql=q.toLowerCase(); const hit=ALL.split(NL).filter(l=>l.toLowerCase().includes(ql)); tb.textContent=hit.length?hit.join(NL):('no lines match: '+q); };
 render('');
 const fi=$('#tfilter'); if(fi){ let t; fi.oninput=()=>{clearTimeout(t);t=setTimeout(()=>render(fi.value.trim()),150);}; }
}

// ---- router -------------------------------------------------------------
// ---- Attack Graph explorer (Cytoscape.js) ----
let CY=null, GScan=null, GSource=null, GTarget=null, GMode='hops', GLast=null, GView=null;
let GVia=new Set();   // optional relationship-type filter for the trace
let GObjective='tier0';  // 'tier0' (paths to Tier-0) or 'all' (everything reachable) for a From-only trace
// Monotonic request token: a slow earlier fetch must NOT render over a newer one (the stale-graph
// bug when quickly replacing the From/To node). Each async view bumps it and checks it before render.
let GNonce=0;
// Detail-panel request token: clicking a node/edge shows its basics INSTANTLY, then enriches from
// the (single-worker, ~0.5s for hubs) node endpoint. Only the LATEST click's fetch may render, so a
// slow earlier response can never paint the wrong node - the recurring "no data / wrong node" bug.
let _detailReq=0;
const KIND_COLOR={AZUser:'#5B9BD5',AZGroup:'#57A773',AZServicePrincipal:'#B07CD6',AZApp:'#9B6FD4',
  AZManagedIdentity:'#3FB0A0',AZRole:'#E0B33A',AZKeyVault:'#E08A3C',AZStorageAccount:'#48B0C4',
  AZSubscription:'#7A8494',AZResourceGroup:'#6B7488',AZManagementGroup:'#8891A8',AZTenant:'#D8DEE9',
  AZVM:'#8A94A8',AZVMScaleSet:'#8A94A8',AZManagedCluster:'#4FB39A',AZContainerRegistry:'#C87D3E',
  AZFunctionApp:'#7FA8D0',AZWebApp:'#7FA8D0',AZLogicApp:'#7FA8D0',AZAutomationAccount:'#7FA8D0',
  AZDevice:'#8A94A8',AZUnknown:'#5C667E'};
const KIND_SHAPE={AZUser:'ellipse',AZGroup:'round-rectangle',AZServicePrincipal:'diamond',AZApp:'rhomboid',
  AZManagedIdentity:'diamond',AZRole:'round-hexagon',AZKeyVault:'barrel',AZStorageAccount:'barrel',
  AZSubscription:'round-rectangle',AZResourceGroup:'round-rectangle',AZManagementGroup:'round-rectangle',
  AZTenant:'star',AZVM:'rectangle',AZVMScaleSet:'rectangle',AZManagedCluster:'round-tag',
  AZContainerRegistry:'rectangle',AZFunctionApp:'rectangle',AZWebApp:'rectangle',AZLogicApp:'rectangle',
  AZAutomationAccount:'rectangle',AZDevice:'rectangle',AZUnknown:'ellipse'};
function _kindColor(k){return KIND_COLOR[k]||'#8891A8';}
function _kindShape(k){return KIND_SHAPE[k]||'ellipse';}
// Minimal-mono type icons: uniform circular nodes, type shown by a light line-icon inside
// (matching the chosen mock). Icons are inlined SVG rendered as node background-image.
const ICON={
  AZUser:'<circle cx="12" cy="8.5" r="4"/><path d="M4.5 20 a7.5 7.5 0 0 1 15 0"/>',
  AZGroup:'<circle cx="9" cy="8" r="3.2"/><path d="M3 19 a6 6 0 0 1 12 0"/><circle cx="17.4" cy="9.4" r="2.5"/><path d="M14.5 19 a5 5 0 0 1 8 -1"/>',
  AZServicePrincipal:'<rect x="5" y="8.5" width="14" height="10.5" rx="3"/><path d="M12 8.5 V5"/><circle cx="12" cy="3.8" r="1.3"/><circle cx="9.5" cy="13.5" r="1.5"/><circle cx="14.5" cy="13.5" r="1.5"/>',
  AZApp:'<rect x="4" y="4" width="7" height="7" rx="1.2"/><rect x="13" y="4" width="7" height="7" rx="1.2"/><rect x="4" y="13" width="7" height="7" rx="1.2"/><rect x="13" y="13" width="7" height="7" rx="1.2"/>',
  AZManagedIdentity:'<circle cx="8" cy="12" r="4"/><path d="M11.5 12 H20 M17 12 V15.5 M20 12 V15"/>',
  AZRole:'<path d="M4 18 L4 8.5 L9.2 12.5 L12 6 L14.8 12.5 L20 8.5 L20 18 Z"/>',
  AZKeyVault:'<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11 V8 a4 4 0 0 1 8 0 V11"/>',
  AZStorageAccount:'<ellipse cx="12" cy="6.5" rx="7" ry="3"/><path d="M5 6.5 V17.5 a7 3 0 0 0 14 0 V6.5"/>',
  AZSubscription:'<path d="M12 3.5 L20.5 8 L12 12.5 L3.5 8 Z"/><path d="M3.5 12 L12 16.5 L20.5 12"/>',
  AZTenant:'<rect x="6" y="4" width="12" height="16" rx="1"/><path d="M9 8 h2 M13 8 h2 M9 12 h2 M13 12 h2 M9 16 h2"/>',
  AZVM:'<rect x="4" y="5.5" width="16" height="5.5" rx="1"/><rect x="4" y="13" width="16" height="5.5" rx="1"/>',
  AZUnknown:'<circle cx="12" cy="12" r="7.5"/>'};
const ICON_ALIAS={AZResourceGroup:'AZSubscription',AZManagementGroup:'AZSubscription',AZVMScaleSet:'AZVM',
  AZManagedCluster:'AZVM',AZContainerRegistry:'AZApp',AZFunctionApp:'AZVM',AZWebApp:'AZVM',
  AZLogicApp:'AZVM',AZAutomationAccount:'AZVM',AZDevice:'AZVM'};
function _iconInner(k){return ICON[k]||ICON[ICON_ALIAS[k]]||ICON.AZUnknown;}
function _iconURI(k,color){
  // Intrinsic width/height + a padded viewBox so Cytoscape fits it proportionally (contain),
  // keeping the icon centred and undistorted at every zoom level. Stroke colour = type colour
  // (red for Tier-0) for at-a-glance identification.
  const c=color||'#D6DCE8';
  const svg='<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="-4 -4 32 32" fill="none" stroke="'+c+'" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">'+_iconInner(k)+'</svg>';
  return 'data:image/svg+xml;utf8,'+encodeURIComponent(svg);
}
function _legendIcon(k){return `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="${_kindColor(k)}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px">${_iconInner(k)}</svg>`;}
// Minimal mono: every node muted slate; colour only carries meaning - crimson = Tier-0,
// amber = on the active attack path. Type is read from the node SHAPE, not colour.
function _cyStyle(){return [
  {selector:'node',style:{'background-color':'#171D28','background-opacity':0.96,'shape':'ellipse','label':'data(label)',
    'background-image':'data(icon)','background-fit':'contain','background-clip':'node',
    'background-image-smoothing':'yes',
    // A solid dark disc gives every node a clear, opaque, well-defined boundary that IS the
    // clickable area (the icon is stroke-only line art, so it sits cleanly on the fill).
    'color':'#AEB7C7','font-size':'9px','font-weight':500,'text-wrap':'ellipsis','text-max-width':'130px',
    'text-valign':'bottom','text-margin-y':4,'text-background-opacity':0,'min-zoomed-font-size':7,
    'text-outline-width':1.4,'text-outline-color':'#0A0C12','text-outline-opacity':0.85,
    'width':26,'height':26,'border-width':2.6,'border-color':'data(color)'}},
  {selector:'node[?onPath]',style:{'border-width':2.6,'border-color':'#E0993F','color':'#E9C79A'}},
  {selector:'node[?tier0]',style:{'background-color':'#241A1D','border-width':3,'border-color':'#E5484D',
    'underlay-color':'#E5484D','underlay-opacity':0.26,'underlay-padding':8,'width':34,'height':34,
    'font-size':'10px','font-weight':700,'color':'#F3A9AD'}},
  // Incidental leaves on a busy view recede so Tier-0 / on-path / hubs carry the eye.
  {selector:'node.gdim',style:{'border-opacity':0.5,'background-image-opacity':0.55}},
  // Selected node is lifted above the pile (z-index) so its white ring/glow is never covered
  // by overlapping neighbours - otherwise the ring only shows when the node happens to be on top.
  {selector:'node:selected',style:{'border-width':3.6,'border-color':'#FFFFFF','underlay-color':'#FFFFFF','underlay-opacity':0.30,'underlay-padding':9,'z-index':9999}},
  {selector:'edge',style:{'width':1.6,'line-color':'#5C687F','opacity':0.85,'curve-style':'bezier','target-arrow-shape':'triangle',
    'target-arrow-color':'#5C687F','arrow-scale':0.8,
    // The relationship type is written along every edge (autorotated). It is gated by
    // min-zoomed-font-size so a dense view reads clean when zoomed out and reveals the
    // labels as you zoom into a region; an outline keeps the text legible over the lines.
    'label':'data(rel)','font-size':'7.5px','color':'#B9C1D2','text-rotation':'autorotate',
    'text-outline-width':2.4,'text-outline-color':'#080A10','text-outline-opacity':0.95,
    'text-background-opacity':0,'min-zoomed-font-size':6}},
  {selector:'edge[?onPath]',style:{'width':2.8,'line-color':'#E0993F','target-arrow-color':'#E0993F','opacity':1,'z-index':10,
    'color':'#F5CE9F','font-size':'9px','font-weight':600,'min-zoomed-font-size':4}},
  // The source node of a focused view (blast radius / paths-from) gets a white ring so the
  // origin stands out in the force layout.
  {selector:'node.groot',style:{'border-width':3.2,'border-color':'#FFFFFF','border-opacity':1,
    'underlay-color':'#FFFFFF','underlay-opacity':0.2,'underlay-padding':7}},
];}
function _decorate(els){
  (els.nodes||[]).forEach(n=>{const col=n.data.tier0?'#E5484D':_kindColor(n.data.kind);n.data.color=col;n.data.icon=_iconURI(n.data.kind,col);});
  // Relationship label written on the edge itself (primitive is the abuse verb, else the raw
  // graph relationship). Spaced out from CamelCase so "CanAddMember" reads "Can Add Member".
  (els.edges||[]).forEach(e=>{const t=e.data.primitive||e.data.type||'';e.data.rel=t.replace(/([a-z])([A-Z])/g,'$1 $2');});
  return els;
}
function _run(o){try{CY.layout(o).run();return true;}catch(e){return false;}}
function _layout(name){
  const n=CY?CY.nodes().length:0;
  let ran=false;
  if(name==='dagre'){
    ran=_run({name:'dagre',rankDir:'LR',nodeSep:24,rankSep:65,animate:false});
  } else {
    // Prefer fcose: an overlap-free force layout that packs disconnected clusters and is fast
    // even on the big overview. On-path edges pull tighter so a traced route reads as a line.
    const fcose={name:'fcose', quality:(n>500?'default':'proof'), animate:false, randomize:true,
      packComponents:true, nodeSeparation:130, nodeRepulsion:()=>7000, gravity:0.28, gravityRange:3.6,
      idealEdgeLength:e=>(e.data('onPath')?70:150), numIter:(n>500?900:2500),
      nodeDimensionsIncludeLabels:true, tile:true, tilingPaddingVertical:14, tilingPaddingHorizontal:14};
    const cose=(n>220)
      ? {name:'cose',animate:false,idealEdgeLength:90,nodeRepulsion:12000,numIter:220,coolingFactor:0.95,componentSpacing:100,nodeOverlap:24,nodeDimensionsIncludeLabels:true}
      : {name:'cose',animate:false,idealEdgeLength:110,nodeRepulsion:20000,numIter:520,componentSpacing:110,nodeOverlap:28,nodeDimensionsIncludeLabels:true};
    ran=_run(fcose)||_run(cose);
  }
  if(!ran)_run({name:'grid'});
  CY.fit(undefined,45);
}
// Size every node by centrality (degree within the view) so hubs read big and leaves small,
// keep Tier-0 prominent, ring the focused source, and - on busy views - hide labels for the
// small unimportant leaves so the graph doesn't drown in text (Tier-0 / on-path / hubs / the
// source keep theirs; every label returns when you zoom in via min-zoomed-font-size + hover).
function _sizeNodes(rootId){
  let mx=1; CY.nodes().forEach(n=>{const d=n.degree(false); if(d>mx)mx=d;});
  const total=CY.nodes().length;
  const declutter=total>40;                                // small graphs: show every label
  CY.nodes().forEach(n=>{
    const d=n.degree(false);
    let sz=Math.round(22+46*Math.sqrt(d/mx));             // ~22..68px, area-proportional to degree
    if(n.data('tier0')&&sz<40)sz=40;                       // Tier-0 stays prominent
    if(rootId&&n.id()===rootId)sz+=12;                     // the focused source reads bigger
    n.data('_baseSize',sz);                                // remember the intended (model) size
    n.style({'width':sz,'height':sz,'font-size':Math.max(8,Math.min(13,Math.round(sz/4.6)))+'px'});
    const important=n.data('tier0')||n.data('onPath')||n.id()===rootId||d>=Math.max(3,mx*0.15);
    n.style('text-opacity', (declutter&&!important)?0:1);
    n.toggleClass('gdim', declutter&&!important);          // fade the incidental leaves
    if(rootId&&n.id()===rootId)n.addClass('groot');
  });
  _applyMinNodeSize();
}
// Cytoscape scales node size with zoom, so a zoomed-out view leaves ~10px targets that are
// hard to click. Enforce a floor on the ON-SCREEN diameter: when zoomed out, grow the model
// size so rendered size (model × zoom) never drops below MIN_NODE_PX; zoomed in, nodes fall
// back to their degree-based `_baseSize`. Called after layout and on every zoom change.
const MIN_NODE_PX=20;
function _applyMinNodeSize(){
  if(!CY)return;
  const z=CY.zoom()||1;
  const floor=MIN_NODE_PX/z;
  CY.batch(()=>{CY.nodes().forEach(n=>{
    const base=n.data('_baseSize')||26;
    const w=Math.max(base,floor);
    n.style({'width':w,'height':w});
  });});
}
// One render path for every view: force-directed layout + centrality sizing on the minimal-mono
// theme. `rootId` (optional) rings the origin node of a focused view (blast radius / paths-from).
function _paintGraph(els,rootId){
  CY.elements().remove();
  CY.add([...(els.nodes||[]),...(els.edges||[])]);
  _sizeNodes(rootId);
  _layout('force');
}
function _renderGraph(els,rootId){_paintGraph(els,rootId||null);}
const _renderBlast=_renderGraph;
function _merge(els){
  const add=[];
  (els.nodes||[]).forEach(n=>{if(!CY.getElementById(n.data.id).length)add.push(n);});
  (els.edges||[]).forEach(e=>{if(!CY.getElementById(e.data.id).length)add.push(e);});
  if(add.length)CY.add(add);
  _sizeNodes();
  _layout('force');
}
// Reveal a node's label on hover even when decluttered.
function _wireHover(){
  if(!CY||CY.__hoverWired)return; CY.__hoverWired=true;
  CY.on('mouseover','node',ev=>ev.target.style('text-opacity',1));
  CY.on('mouseout','node',ev=>{const n=ev.target;if(n.hasClass('gdim'))n.style('text-opacity',0);});
}
function _legendHTML(){
  return '<div style="display:flex;flex-direction:column;gap:6px">'
    +'<span><span class="gdot" style="background:#241A1D;box-shadow:0 0 0 2px #E5484D"></span>Tier-0 target (red)</span>'
    +'<span><span class="gdot" style="background:#1B212E;box-shadow:0 0 0 2px #E0993F"></span>On the attack path (amber)</span>'
    +'<div style="color:var(--tx3);font-size:11px;margin-top:4px;line-height:1.9">Colour + icon = type '
    +['AZUser','AZGroup','AZServicePrincipal','AZRole','AZKeyVault','AZStorageAccount','AZSubscription'].map(k=>`<span style="margin-right:9px;white-space:nowrap;color:${_kindColor(k)}">${_legendIcon(k)} ${k.replace('AZ','')}</span>`).join('')
    +'</div>'
    +'</div>';
}
function _setSource(id,label){GSource={id:id,label:label};const i=$('#gsrc');if(i)i.value=label;}
function _setTarget(id,label){GTarget={id:id,label:label};const i=$('#gtgt');if(i)i.value=label;}
// Select a node in the graph (if present in the current view), centre it, and show its detail
// panel immediately - so picking a From/To from search reveals that node without a manual click.
function _focusNode(id,label){
  try{const el=CY&&CY.getElementById(id);
    if(el&&el.nonempty()){CY.$(':selected').unselect();el.select();CY.animate({center:{eles:el}},{duration:200});}
  }catch(e){}
  _showNode({id:id,label:label});
}
async function _loadOverview(){
  const n=++GNonce; GLast=_loadOverview; GView={kind:'overview'};
  $('#gmsg').textContent='Loading all attack paths to Tier-0…';
  try{const els=await api('/api/scans/'+GScan+'/graph/overview'); if(n!==GNonce)return;
    _renderGraph(_decorate(els));$('#gmsg').textContent=els.message||'';
  }catch(e){if(n===GNonce)$('#gmsg').textContent=e.message;}
}
async function _pathsToTier0(id,label){
  const n=++GNonce; const via=[...GVia];
  GLast=()=>_pathsToTier0(id,label); GView={kind:'paths',source:id,label:label||null,mode:GMode,via:via};
  $('#gmsg').textContent='Finding '+(GMode==='easiest'?'easiest':'shortest')+' paths to Tier-0…';
  const viaQ=via.length?('&via='+encodeURIComponent(via.join(','))):'';
  try{const els=await api('/api/scans/'+GScan+'/graph/paths-to-tier0?source='+encodeURIComponent(id)+'&mode='+GMode+viaQ); if(n!==GNonce)return;
    _renderGraph(_decorate(els),id);$('#gmsg').textContent=els.message||'';
  }catch(e){if(n===GNonce)$('#gmsg').textContent=e.message;}
}
// From-only objective "all": everything reachable from the node (any target, not just Tier-0),
// optionally constrained by the Via relationship filter.
async function _reachableFrom(id,label){
  const n=++GNonce; const via=[...GVia];
  GLast=()=>_reachableFrom(id,label); GView={kind:'reach',source:id,label:label||null,via:via};
  $('#gmsg').textContent='Finding everything reachable from '+(label||'node')+'…';
  const viaQ=via.length?('&via='+encodeURIComponent(via.join(','))):'';
  try{const els=await api('/api/scans/'+GScan+'/graph/reachable?source='+encodeURIComponent(id)+viaQ); if(n!==GNonce)return;
    _renderGraph(_decorate(els),id);$('#gmsg').textContent=els.message||'';
  }catch(e){if(n===GNonce)$('#gmsg').textContent=e.message;}
}
// Route a From-only trace to the selected objective.
function _traceFrom(id,label){return GObjective==='all'?_reachableFrom(id,label):_pathsToTier0(id,label);}
async function _blastRadius(id,label){
  const n=++GNonce; GLast=()=>_blastRadius(id,label); GView={kind:'blast',source:id,label:label||null};
  $('#gmsg').textContent='Computing blast radius…';
  try{const els=await api('/api/scans/'+GScan+'/graph/blast-radius?source='+encodeURIComponent(id)); if(n!==GNonce)return;
    _renderBlast(_decorate(els),id);$('#gmsg').textContent=els.message||'';
  }catch(e){if(n===GNonce)$('#gmsg').textContent=e.message;}
}
// Opt-in view: the node's DIRECT relationships across ALL edge types (not just escalation
// → Tier-0). Exactly one hop - the node plus everything it is directly connected to.
async function _allRelations(id,label){
  const n=++GNonce; GLast=()=>_allRelations(id,label); GView={kind:'allrel',source:id,label:label||null};
  $('#gmsg').textContent='Mapping all relationships…';
  try{const els=await api('/api/scans/'+GScan+'/graph/all-relations?source='+encodeURIComponent(id)); if(n!==GNonce)return;
    _renderGraph(_decorate(els),id);$('#gmsg').textContent=els.message||'';
  }catch(e){if(n===GNonce)$('#gmsg').textContent=e.message;}
}
async function _pathsToTarget(id,label){
  const n=++GNonce; GLast=()=>_pathsToTarget(id,label); GView={kind:'pathsto',target:id,label:label||null};
  $('#gmsg').textContent='Finding all paths to '+(label||'target')+'…';
  try{const els=await api('/api/scans/'+GScan+'/graph/paths-to?target='+encodeURIComponent(id)); if(n!==GNonce)return;
    _renderGraph(_decorate(els),id);$('#gmsg').textContent=els.message||'';   // ring the objective
  }catch(e){if(n===GNonce)$('#gmsg').textContent=e.message;}
}
// Human-readable relationship label: "CanGrantRole" → "Can Grant Role".
function _viaLabel(t){return t.replace(/([a-z])([A-Z])/g,'$1 $2');}
function _viaSummary(){$('#gviasum').textContent='Via: '+(GVia.size?(GVia.size+' type'+(GVia.size>1?'s':'')):'any');}
// Build the optional "Via" relationship-type checklist from the scan's actual edge types.
async function _loadViaOptions(){
  const list=$('#gvialist'); if(!list)return;
  try{const m=await api('/api/scans/'+GScan+'/graph/meta');
    const types=(m.edge_types||[]);
    list.innerHTML=types.map(t=>`<label><input type="checkbox" value="${esc(t)}"${GVia.has(t)?' checked':''}> ${esc(_viaLabel(t))}</label>`).join('')
      +(types.length?`<button class="btn ghost sm gviaclear" id="gviaclear">Clear</button>`:'<span class="muted small">No relationships in this scan.</span>');
    list.querySelectorAll('input[type=checkbox]').forEach(cb=>cb.onchange=()=>{
      if(cb.checked)GVia.add(cb.value);else GVia.delete(cb.value);_viaSummary();});
    const clr=$('#gviaclear'); if(clr)clr.onclick=(e)=>{e.preventDefault();GVia.clear();list.querySelectorAll('input').forEach(cb=>cb.checked=false);_viaSummary();};
  }catch(e){}
  _viaSummary();
}
async function _pathBetween(){
  // Only a "To" set (no "From") → show everything that can reach that objective.
  if(!GSource&&GTarget){_pathsToTarget(GTarget.id,GTarget.label);return;}
  if(!GSource){toast('Pick a "From" or "To" node first.');return;}
  if(!GTarget){_traceFrom(GSource.id,GSource.label);return;}   // From only → objective-driven
  const n=++GNonce; const via=[...GVia];
  GLast=_pathBetween; GView={kind:'path',source:GSource.id,target:GTarget.id,label:(GSource.label||'')+' → '+(GTarget.label||''),mode:GMode,via:via};
  $('#gmsg').textContent='Finding path…';
  const viaQ=via.length?('&via='+encodeURIComponent(via.join(','))):'';
  try{const els=await api('/api/scans/'+GScan+'/graph/path?source='+encodeURIComponent(GSource.id)+'&target='+encodeURIComponent(GTarget.id)+'&mode='+GMode+viaQ); if(n!==GNonce)return;
    _renderGraph(_decorate(els),GSource.id);$('#gmsg').textContent=els.message||'';
  }catch(e){if(n===GNonce)$('#gmsg').textContent=e.message;}
}
async function _expand(id){
  try{const els=await api('/api/scans/'+GScan+'/graph/expand?node='+encodeURIComponent(id));
    _merge(_decorate(els));$('#gmsg').textContent=els.message||'Expanded neighbours.';
  }catch(e){$('#gmsg').textContent=e.message;}
}
async function _toggleTier0(id,make){
  try{
    const base='/api/scans/'+GScan+'/graph/tier0';
    if(make){await api(base,{method:'POST',body:new URLSearchParams({id:id})});}
    else{await api(base+'?id='+encodeURIComponent(id),{method:'DELETE'});}
    toast(make?'Marked as Tier-0.':'Removed from Tier-0.');
    _loadOverview();
  }catch(e){toast('Failed: '+e.message);}
}
// Reset the graph: clear this scan's custom Tier-0 marks and all view state, back to overview.
async function _clearGraph(){
  try{await api('/api/scans/'+GScan+'/graph/tier0/clear',{method:'POST'});}catch(e){}
  GSource=null; GTarget=null; GVia.clear(); GObjective='tier0';
  const s=$('#gsrc'),t=$('#gtgt'),o=$('#gobj');
  if(s)s.value=''; if(t)t.value=''; if(o)o.value='tier0';
  _viaSummary();
  $('#gvialist')&&$('#gvialist').querySelectorAll('input[type=checkbox]').forEach(cb=>cb.checked=false);
  toast('Graph reset.');
  _defaultSide(); _defaultDetail(); _loadOverview();
}
// Loader: render the node's basics immediately (never a blank/Loading dead-end), then enrich
// from the endpoint - but only if this is still the latest click (nonce guard).
async function _showNode(basic){
  const my=++_detailReq;
  _renderNode(basic, true);                 // instant paint from the data cytoscape already has
  let d=basic; try{d=await api('/api/scans/'+GScan+'/graph/node?id='+encodeURIComponent(basic.id));}catch(e){}
  if(my!==_detailReq) return;               // a newer click (or edge/default) superseded this one
  _renderNode(d, false);
}
function _renderNode(d, partial){
  const side=$('#gdetail'); if(!side)return;
  const flags=[];
  if(d.tier0)flags.push('<b style="color:var(--med)">Tier-0</b>');
  if(d.critical)flags.push('<span style="color:var(--crit)">critical</span>');
  if(d.eligible)flags.push('PIM-eligible');
  if(d.reaches_tier0&&!d.tier0)flags.push('<span style="color:var(--high)">reaches Tier-0</span>');
  const props=Object.entries(d.props||{}).map(([k,v])=>`<div class="prow"><span class="pk">${esc(k)}</span><span class="pv">${esc(String(v))}</span></div>`).join('')||'<div class="muted small">No collected properties.</div>';
  const tags=(d.tags||[]).length?`<div class="k">Tags</div><div class="gtags">${(d.tags||[]).map(t=>`<span class="tagpill">${esc(t)}</span>`).join('')}</div>`:'';
  const t0btn=d.custom_tier0?`<button class="btn ghost sm" id="gt0btn">✕ Remove Tier-0</button>`
    :(d.tier0?'':`<button class="btn ghost sm" id="gt0btn">★ Mark Tier-0</button>`);
  const canDo=Object.entries(d.out_primitives||{});
  const rel=(d.related_findings||[]).filter(f=>f.title);
  const t0r=(d.tier0_reasons||[]);
  const t0html=t0r.length?`<div class="k">Why Tier-0</div><div class="gprops">${t0r.map(r=>`<div class="t0reason"><div class="t0lbl">${esc(r.label)}</div><div class="t0desc">${esc(r.desc)}</div></div>`).join('')}</div>`:'';
  side.innerHTML=`<h3 style="margin:0 0 2px">${esc(d.label)}</h3>
    <div class="muted small">${esc((d.kind||'').replace('AZ',''))} · in ${d.in_degree||0} / out ${d.out_degree||0}${flags.length?' · '+flags.join(' · '):''}</div>
    <div class="k">Actions</div>
    <div class="gactions">
      <button class="btn sm" id="gapaths">Paths to Tier-0</button>
      <button class="btn ghost sm" id="gablast" title="Everything this node can reach downstream via escalation edges, ranked by impact">Blast radius</button>
      <button class="btn ghost sm" id="gaall" title="The node's DIRECT relationships across ALL edge types (one hop only) - everything it is directly connected to, not just escalation paths">All relationships</button>
      <button class="btn ghost sm" id="gaexp">Expand</button>
      <button class="btn ghost sm" id="gasrc">Set as From</button>
      <button class="btn ghost sm" id="gatgt">Set as To</button>
      ${t0btn}
    </div>
    ${t0html}
    <div class="k">Attack summary</div>
    <div class="muted small" style="line-height:1.65">Reaches <b style="color:var(--tx)">${d.reaches_tier0_count||0}</b> Tier-0 target(s)${d.nearest_tier0_hops!=null?(' · nearest '+d.nearest_tier0_hops+' hop(s)'):''}<br><b style="color:var(--tx)">${d.attackers_count||0}</b> node(s) can reach this</div>
    ${canDo.length?`<div class="k">Can perform</div><div class="gtags">${canDo.map(([p,c])=>`<span class="tagpill">${esc(p)}${c>1?(' ×'+c):''}</span>`).join('')}</div>`:''}
    ${rel.length?`<div class="k">Related findings</div><div class="gprops">${rel.map(f=>`<div class="gitem">${esc(f.severity?('['+f.severity+'] '):'')}${esc(f.title)}</div>`).join('')}</div>`:''}
    <div class="k">Properties</div><div class="gprops">${props}</div>
    ${tags}
    <div class="k">Node id</div><div class="gid">${esc(d.id)}</div>
    ${partial?'<div class="muted small" style="margin-top:8px"><span class="spin"></span> loading full details…</div>':''}`;
  $('#gapaths').onclick=()=>{_setSource(d.id,d.label);_pathsToTier0(d.id,d.label);};
  $('#gablast').onclick=()=>{_setSource(d.id,d.label);_blastRadius(d.id,d.label);};
  $('#gaall').onclick=()=>{_setSource(d.id,d.label);_allRelations(d.id,d.label);};
  $('#gaexp').onclick=()=>_expand(d.id);
  $('#gasrc').onclick=()=>{_setSource(d.id,d.label);toast('From: '+d.label);};
  $('#gatgt').onclick=()=>{_setTarget(d.id,d.label);toast('To: '+d.label);};
  const tb=$('#gt0btn'); if(tb)tb.onclick=()=>_toggleTier0(d.id,!d.custom_tier0);
}
async function _showEdge(basic){
  const my=++_detailReq;
  const side=$('#gdetail');
  side.innerHTML='<p class="muted small">Loading edge…</p>';
  let d=null; try{d=await api('/api/scans/'+GScan+'/graph/edge?id='+encodeURIComponent(basic.id));}catch(e){}
  if(my!==_detailReq) return;               // superseded by a newer click
  if(!d){side.innerHTML='<p class="muted small">No detail for this edge.</p>';return;}
  const cond=(d.conditions||[]).length?`<div class="k">Requires</div><div class="gtags">${d.conditions.map(c=>`<span class="tagpill">${esc(c.replace(/_/g,' '))}</span>`).join('')}</div>`:'';
  const ev=Object.entries(d.evidence||{}).map(([k,v])=>`<div class="prow"><span class="pk">${esc(k)}</span><span class="pv">${esc(Array.isArray(v)?v.join(' → '):String(v))}</span></div>`).join('');
  const rel=(d.related_findings||[]).filter(f=>f.title).map(f=>`<div class="gitem">${esc(f.severity?('['+f.severity+'] '):'')}${esc(f.title)}</div>`).join('')||'<div class="muted small">None linked.</div>';
  side.innerHTML=`<h3 style="margin:0 0 2px">${esc(d.primitive||d.type)}</h3>
    <div class="muted small">${esc(d.source.label)} → ${esc(d.target.label)}${d.target.tier0?' · <b style="color:var(--crit)">Tier-0</b>':''}</div>
    <div class="k">Why this edge exists</div><p style="margin:0;font-size:12.5px;line-height:1.55">${esc(d.why||'-')}</p>
    <div class="k">Difficulty</div><div class="muted small">weight ${d.weight} · ${esc(d.type)}${d.count>1?(' · '+d.count+' assignment(s)'):''}</div>
    ${cond}
    ${ev?`<div class="k">Evidence</div><div class="gprops">${ev}</div>`:''}
    <div class="k">Related findings</div><div class="gprops">${rel}</div>`;
}
function _attachSearch(inp,sug,onPick){let t=null;
  inp.oninput=()=>{clearTimeout(t);const q=inp.value.trim();if(q.length<2){sug.hidden=true;return;}
    t=setTimeout(async()=>{try{const r=await api('/api/scans/'+GScan+'/graph/search?q='+encodeURIComponent(q));
      sug.innerHTML=(r.results||[]).map(n=>`<div data-id="${esc(n.id)}" data-label="${esc(n.label)}">${n.tier0?'★ ':''}${esc(n.label)} <span class="muted small">${esc((n.kind||'').replace('AZ',''))}</span></div>`).join('')||'<div class="muted small" style="padding:8px 11px">No matches</div>';
      sug.hidden=false;
      qa('div[data-id]',sug).forEach(x=>x.onclick=()=>{sug.hidden=true;inp.value=x.dataset.label;onPick(x.dataset.id,x.dataset.label);});
    }catch(e){}},220);};
  inp.onblur=()=>setTimeout(()=>{sug.hidden=true;},180);
}
function _defaultSide(){
  const s=$('#gside'); if(!s)return;
  s.innerHTML=`<div class="k">Prebuilt queries</div><div id="gpresets" class="gpresets muted small">Loading…</div>
    <div class="k">Saved queries <button class="linkbtn" id="gsavebtn" title="Save the current view">+ save current</button></div><div id="gsaved" class="gpresets muted small">…</div>
    <div class="k">Attack paths <span class="muted small" id="gpathct"></span></div><div id="gpaths" class="muted small">Loading…</div>
    <div class="k">Legend</div><div class="glegend">${_legendHTML()}</div>
    <div class="k">Custom Tier-0</div><div id="gt0list" class="muted small">…</div>`;
  const sb=$('#gsavebtn'); if(sb)sb.onclick=_saveCurrentView;
  _renderPresets(); _renderSaved(); _renderPathsList(); _renderTier0List();
}
function _defaultDetail(){
  ++_detailReq;                             // cancel any in-flight node/edge fetch
  const d=$('#gdetail'); if(!d)return;
  d.innerHTML='<div class="k">Details</div><p class="muted small">Click a node or an edge in the graph for its full details here. Choose a path or query on the left to populate the graph.</p>';
}
async function _renderPresets(){
  const el=$('#gpresets'); if(!el)return;
  try{const r=await api('/api/scans/'+GScan+'/graph/presets');
    el.innerHTML=(r.presets||[]).map(p=>`<button class="qbtn" data-preset="${esc(p.name)}" title="${esc(p.desc)}">${esc(p.label)}</button>`).join('');
    qa('button[data-preset]',el).forEach(b=>b.onclick=()=>_runPreset(b.dataset.preset,b.textContent));
  }catch(e){el.textContent='';}
}
async function _runPreset(name,label){
  const n=++GNonce; GLast=()=>_runPreset(name,label); GView={kind:'preset',preset:name,label:label||name};
  $('#gmsg').textContent='Running: '+(label||name)+'…';
  try{const els=await api('/api/scans/'+GScan+'/graph/preset?name='+encodeURIComponent(name)); if(n!==GNonce)return;
    _renderGraph(_decorate(els));$('#gmsg').textContent=els.message||'';
  }catch(e){if(n===GNonce)$('#gmsg').textContent=e.message;}
}
async function _renderPathsList(){
  const el=$('#gpaths'); if(!el)return;
  try{const r=await api('/api/scans/'+GScan+'/graph/paths-list');
    const ct=$('#gpathct'); if(ct)ct.textContent=r.paths.length?('('+r.paths.length+')'):'';
    if(!r.paths.length){el.textContent='No escalation paths to Tier-0.';return;}
    el.innerHTML='<div class="gpathlist">'+r.paths.map(p=>`<div class="gpath" data-src="${esc(p.source)}" title="${esc(p.source_label)} reaches ${p.reaches} Tier-0 target(s)"><span class="gpk">${_legendIcon(p.source_kind)} ${esc(p.source_label)}</span><span class="gph">reaches ${p.reaches} · nearest ${p.hops}h → ${esc(p.target_label)}</span></div>`).join('')+'</div>';
    qa('.gpath',el).forEach(x=>x.onclick=()=>{const lbl=x.querySelector('.gpk').textContent.trim();_setSource(x.dataset.src,lbl);_traceFrom(x.dataset.src,lbl);});
  }catch(e){el.textContent='';}
}
function _viewDesc(v){v=v||{};
  if(v.kind==='overview')return 'All attack paths to Tier-0';
  if(v.kind==='preset')return 'Query: '+(v.label||v.preset);
  if(v.kind==='blast')return 'Blast radius from '+(v.label||v.source||'a node');
  if(v.kind==='path')return 'Path: '+(v.label||(v.source+' → '+v.target));
  if(v.kind==='paths')return 'Paths to Tier-0 from '+(v.label||v.source||'a node');
  if(v.kind==='reach')return 'Everything reachable from '+(v.label||v.source||'a node');
  return v.kind||'view';}
function _replayView(v){v=v||{};
  if(v.mode==='hops'||v.mode==='easiest'){GMode=v.mode;const mb=$('#gmode');if(mb)mb.textContent='Ranking: '+(GMode==='easiest'?'Easiest':'Shortest');}
  if(v.kind==='preset')return _runPreset(v.preset,v.label);
  if(v.kind==='blast'){_setSource(v.source,v.label||v.source);return _blastRadius(v.source,v.label);}
  if(v.kind==='path'){_setSource(v.source,v.source);_setTarget(v.target,v.target);
    GVia=new Set(v.via||[]);_viaSummary();
    $('#gvialist')&&$('#gvialist').querySelectorAll('input[type=checkbox]').forEach(cb=>cb.checked=GVia.has(cb.value));
    return _pathBetween();}
  if(v.kind==='paths'){_setSource(v.source,v.label||v.source);
    GVia=new Set(v.via||[]);_viaSummary();
    $('#gvialist')&&$('#gvialist').querySelectorAll('input[type=checkbox]').forEach(cb=>cb.checked=GVia.has(cb.value));
    return _pathsToTier0(v.source,v.label);}
  if(v.kind==='pathsto'){_setTarget(v.target,v.label||v.target);return _pathsToTarget(v.target,v.label);}
  if(v.kind==='reach'){_setSource(v.source,v.label||v.source);GObjective='all';const o=$('#gobj');if(o)o.value='all';
    GVia=new Set(v.via||[]);_viaSummary();
    $('#gvialist')&&$('#gvialist').querySelectorAll('input[type=checkbox]').forEach(cb=>cb.checked=GVia.has(cb.value));
    return _reachableFrom(v.source,v.label);}
  return _loadOverview();}
async function _renderSaved(){
  const el=$('#gsaved'); if(!el)return;
  try{const r=await api('/api/graph/saved-queries');const qs=r.queries||[];
    if(!qs.length){el.innerHTML='<span class="muted small">None saved. Build a view, then “+ save current”.</span>';return;}
    el.innerHTML=qs.map(q=>`<div class="gsq"><button class="qbtn" data-sq="${esc(q.name)}" title="${esc(_viewDesc(q.view))}">${esc(q.name)}</button><button class="linkbtn" data-sqrm="${esc(q.name)}" title="Delete">✕</button></div>`).join('');
    qa('button[data-sq]',el).forEach(b=>b.onclick=()=>{const q=qs.find(x=>x.name===b.dataset.sq);if(q)_replayView(q.view);});
    qa('button[data-sqrm]',el).forEach(b=>b.onclick=()=>_removeSaved(b.dataset.sqrm));
  }catch(e){el.textContent='';}
}
async function _saveCurrentView(){
  if(!GView){toast('Build a view first (a query, path, or blast radius), then save it.');return;}
  const name=(prompt('Save this view as:',_viewDesc(GView))||'').trim();
  if(!name)return;
  try{await api('/api/graph/saved-queries',{method:'POST',body:new URLSearchParams({name:name,view:JSON.stringify(GView)})});
    toast('Saved: '+name);_renderSaved();
  }catch(e){toast('Save failed: '+e.message);}
}
async function _removeSaved(name){
  try{await api('/api/graph/saved-queries?name='+encodeURIComponent(name),{method:'DELETE'});_renderSaved();}catch(e){}
}
async function _renderTier0List(){
  const el=$('#gt0list'); if(!el)return;
  try{const r=await api('/api/scans/'+GScan+'/graph/tier0');const ids=r.custom_tier0||[];
    el.innerHTML=ids.length?ids.map(id=>`<div class="prow"><span class="pv" style="word-break:break-all">${esc(id)}</span><button class="linkbtn" data-rm="${esc(id)}">remove</button></div>`).join(''):'None yet.';
    qa('button[data-rm]',el).forEach(b=>b.onclick=()=>_toggleTier0(b.dataset.rm,false));
  }catch(e){el.textContent='';}
}
async function viewGraph(scanId,focusId,targetId){
  const app=$('#app'); GSource=null; GTarget=null;
  let scans=[]; try{scans=await api('/api/scans');}catch(e){}
  if(!scans.length){app.innerHTML='<h1>Attack Graph</h1><p class="sub">No scans yet - run a scan first.</p>';return;}
  GScan = (scanId && scans.some(s=>s.id===scanId)) ? scanId : scans[0].id;
  const opts=scans.map(s=>`<option value="${esc(s.id)}" ${s.id===GScan?'selected':''}>${esc(fmtDate(s.created_at))} · ${esc(s.grade||'?')} (${s.score||0})</option>`).join('');
  app.innerHTML=`<h1>Attack Graph</h1>
   <p class="sub">Interactive map of the identity attack graph - all escalation paths to Tier-0. Everything is muted; only <b style="color:#E5484D">Tier-0 targets</b> and the <b style="color:#E0993F">active attack path</b> carry colour. The icon inside each node encodes its type.</p>
   <div id="gstage">
   <div class="gtoolbar">
     <select id="gscan" title="Scan">${opts}</select>
     <div class="gsearchbox"><input id="gsrc" type="search" placeholder="From: principal…" autocomplete="off"><div class="gsug" id="gsrcsug" hidden></div></div>
     <div class="gsearchbox"><input id="gtgt" type="search" placeholder="To (optional): target…" autocomplete="off"><div class="gsug" id="gtgtsug" hidden></div></div>
     <details class="gvia" id="gviabox" title="Optional: restrict traced paths to specific relationship types (e.g. CanGrantRole, CanStealManagedIdentity)."><summary id="gviasum">Via: any</summary><div class="gvialist" id="gvialist"></div></details>
     <select id="gobj" title="For a From-only trace: reach Tier-0 targets, or everything reachable from the node"><option value="tier0">Reach: Tier-0</option><option value="all">Reach: All</option></select>
     <button class="btn sm" id="gtrace">Trace</button>
     <button class="btn ghost sm" id="gmode" title="Rank paths by fewest hops, or by lowest total difficulty (most likely)">Ranking: Shortest</button>
     <button class="btn ghost sm" id="gall">All paths</button>
     <button class="btn ghost sm" id="gclear" title="Reset the graph: clear this scan's custom Tier-0 marks and the From/To/Via/Reach selection, back to the default overview">Clear</button>
     <button class="btn ghost sm" id="gfit">Fit</button>
     <button class="btn ghost sm" id="gfull" title="Toggle full screen">⛶ Full screen</button>
     <span class="gmsg" id="gmsg"></span>
   </div>
   <div class="gwrap">
     <div class="gside" id="gside"></div>
     <div id="cy"></div>
     <div id="gdetail"></div>
   </div>
   </div>`;
  if(typeof cytoscape==='undefined'){$('#gmsg').textContent='Graph library failed to load.';return;}
  CY=cytoscape({container:$('#cy'),style:_cyStyle(),wheelSensitivity:0.25,
    pixelRatio:1,textureOnViewport:true,hideEdgesOnViewport:true,motionBlur:false,
    autoungrabify:false});
  _wireHover();
  // Forgiving selection: a dense/zoomed-out graph packs nodes closer than a fingertip, so
  // instead of requiring a pixel-perfect hit we select the node whose CENTRE is nearest the
  // click, within a generous screen-space radius. Falls through to an edge only when the click
  // is genuinely near a line and not a node, and to the default panel when near neither.
  const TAP_RADIUS_PX=44;
  // Click → detail panel. PRIMARY path is cytoscape's own hit-test via ev.target: a tap anywhere
  // on a node's body (ANY size - the old distance-threshold missed the edge of big hub nodes,
  // which is why clicks "sometimes" showed nothing) selects it. Only a background tap falls back
  // to a nearest-node search (for the gaps between tiny overlapping nodes), else clears the panel.
  function _resolveTap(ev){
    const t=ev.target;
    if(t && t!==CY && t.isNode && t.isNode()){ CY.$(':selected').unselect(); t.select(); _showNode(t.data()); return; }
    if(t && t!==CY && t.isEdge && t.isEdge()){ _showEdge(t.data()); return; }
    // background tap: forgiving nearest-node within a generous screen radius, for the gaps
    // between tiny overlapping nodes. (On-node clicks are already handled above via ev.target,
    // so this never needs the node's own size.)
    const p=ev.position, thr=TAP_RADIUS_PX/(CY.zoom()||1);
    let best=null, bd=thr;
    CY.nodes().forEach(n=>{const q=n.position();const d=Math.hypot(p.x-q.x,p.y-q.y);if(d<bd){bd=d;best=n;}});
    if(best){ CY.$(':selected').unselect(); best.select(); _showNode(best.data()); return; }
    _defaultDetail();
  }
  CY.on('tap', _resolveTap);
  // Keep the on-screen node size above the click-target floor as the user zooms (throttled).
  let _zRAF=null;
  CY.on('zoom',()=>{if(_zRAF)return;_zRAF=requestAnimationFrame(()=>{_zRAF=null;_applyMinNodeSize();});});
  $('#gscan').onchange=e=>{location.hash='#/graph/'+e.target.value;};
  $('#gall').onclick=()=>{_defaultSide();_loadOverview();};
  $('#gclear').onclick=_clearGraph;
  $('#gtrace').onclick=_pathBetween;
  $('#gmode').onclick=()=>{GMode=(GMode==='hops'?'easiest':'hops');$('#gmode').textContent='Ranking: '+(GMode==='easiest'?'Easiest':'Shortest');if(GLast)GLast();};
  $('#gfit').onclick=()=>CY.fit(undefined,45);
  $('#gfull').onclick=()=>{const st=$('#gstage');if(!document.fullscreenElement){st.requestFullscreen&&st.requestFullscreen();}else{document.exitFullscreen&&document.exitFullscreen();}};
  document.onfullscreenchange=()=>{const on=!!document.fullscreenElement;const b=$('#gfull');if(b)b.textContent=on?'⛶ Exit full screen':'⛶ Full screen';setTimeout(()=>{if(CY){CY.resize();CY.fit(undefined,45);}},120);};
  _attachSearch($('#gsrc'),$('#gsrcsug'),(id,label)=>{_setSource(id,label);_traceFrom(id,label);});
  _attachSearch($('#gtgt'),$('#gtgtsug'),(id,label)=>{_setTarget(id,label);_focusNode(id,label);});
  const gobj=$('#gobj'); if(gobj)gobj.onchange=()=>{GObjective=gobj.value;
    if(GSource&&!GTarget)_traceFrom(GSource.id,GSource.label);};   // re-run the From-only trace
  GVia.clear(); GObjective='tier0'; const _go=$('#gobj'); if(_go)_go.value='tier0';
  _loadViaOptions();                               // populate the optional "Via" relationship filter
  _defaultSide(); _defaultDetail();
  if(focusId&&targetId){
    // Opened from a finding that has its own target: plot the finding's actual path
    // (entry -> the finding's target), not a generic path to Tier-0.
    _setSource(focusId,focusId);_setTarget(targetId,targetId);_pathBetween();_showNode({id:focusId});
  }
  else if(focusId){_setSource(focusId,focusId);_pathsToTier0(focusId,focusId);_showNode({id:focusId});}
  else{_loadOverview();}
}

const routes={dashboard:viewDashboard,scan:viewScan,history:viewHistory,graph:viewGraph,rules:viewRules,traces:viewTraces,settings:viewSettings};
function router(){const parts=(location.hash.replace('#/','')||'dashboard').split('/');const base=parts[0];setNav(base);const m=document.querySelector('main');if(m)m.classList.toggle('graphwide',base==='graph');if(base==='job'){viewJob(parts[1]);}else if(base==='trace'){viewTrace(parts[1]);}else if(base==='graph'){viewGraph(parts[1],parts[2]?decodeURIComponent(parts[2]):null,parts[3]?decodeURIComponent(parts[3]):null);}else{(routes[base]||viewDashboard)();}}
window.addEventListener('hashchange',router);
// Clicking a nav link whose hash is already current fires no hashchange, so the view
// (and, for the graph, its presets) would not refresh. Re-run the router on that no-op
// click so every navigation re-fetches - the graph explorer always shows current presets.
document.querySelectorAll('nav a[href^="#/"]').forEach(a=>a.addEventListener('click',()=>{
  if(location.hash===a.getAttribute('href')) router();
}));
if(new URLSearchParams(location.search).get('embed'))document.body.classList.add('embed');
_boot();
</script></body></html>"""
