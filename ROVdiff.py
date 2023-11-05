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
    tals = data["tals"]
    return tals, cacerts, roas

def diffROV(file, tals, cacerts, roas):
    with open(file, 'r') as f:
        data = json.load(f)
    tals2, cas2, roas2 = data["tals"], data["ca_certs"], data["roas"]
    cachanges = []
    roachanges = []
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
    return cachanges, roachanges

if len(sys.argv) != 4:
    print("Usage: python ROVdiff.py file1 file2 out")
    sys.exit(1)

file1 = sys.argv[1]
file2 = sys.argv[2]
out = sys.argv[3]

tals, ca_certs, roas = genROV(file1)
cachanges, roachanges = diffROV(file2, tals, ca_certs, roas)
res = {"cadiff": cachanges, "roadiff": roachanges}

with open(out, 'w') as f:
    json.dump(res, f, indent=2)