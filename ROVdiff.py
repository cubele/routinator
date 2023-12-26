import sys
import json

def genROV(file):
    with open(file, 'r') as f:
        data = json.load(f)
    cacerts = {}
    for ca in data["ca_certs"]:
        cacerts[ca["id"]] = ca
    roas = {}
    for roa in data["roas"]:
        roas[roa["id"]] = roa
    tals = {}
    for tal in data["tals"]:
        tals[tal["name"]] = tal
    return tals, cacerts, roas

def diffROV(file1, file2):
    cachanges = []
    roachanges = []
    talchanges = []
    talchanged = False
    tals, cacerts, roas = genROV(file1) # old
    with open(file2, 'r') as f:
        data = json.load(f)
    tals2, cas2, roas2 = data["tals"], data["ca_certs"], data["roas"] # new
    for ca in cas2:
        caid = ca["id"]
        if not caid in cacerts:
            cachanges.append({"before": {}, "after": ca})
        elif cacerts[caid] != ca:
            cachanges.append({"before": cacerts[caid], "after": ca})
    for roa in roas2:
        roaid = roa["id"]
        if not roaid in roas:
            roachanges.append({"before": {}, "after": roa})
        elif roas[roaid] != roa:
            roachanges.append({"before": roas[roaid], "after": roa})
    for tal in tals2:
        talname = tal["name"]
        if not talname in tals or tals[talname] != tal:
            talchanged = True

    tals, cacerts, roas = genROV(file2)
    with open(file1, 'r') as f:
        data = json.load(f)
    tals1, cas1, roas1 = data["tals"], data["ca_certs"], data["roas"] # old
    for ca in cas1:
        caid = ca["id"]
        if not caid in cacerts:
            cachanges.append({"before": ca, "after": {}})
    for roa in roas1:
        roaid = roa["id"]
        if not roaid in roas:
            roachanges.append({"before": roa, "after": {}})
    for tal in tals1:
        talname = tal["name"]
        if not talname in tals or tals[talname] != tal:
            talchanged = True
    if talchanged:
        talchanges = [tals1, tals2]
    
    return talchanges, cachanges, roachanges

if len(sys.argv) != 4:
    print("Usage: python ROVdiff.py file1 file2 out")
    sys.exit(1)

file1 = sys.argv[1]
file2 = sys.argv[2]
out = sys.argv[3]

talchanges, cachanges, roachanges = diffROV(file1, file2)
res = {"taldiff": talchanges, "cadiff": cachanges, "roadiff": roachanges}

with open(out, 'w') as f:
    json.dump(res, f, indent=2)