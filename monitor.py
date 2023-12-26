import os, time
from datetime import datetime
import subprocess
INTERVAL = 20 * 60
if not os.path.isfile("./output/ROV.json"):
    fout = open("./output/ROV.json", "w")
    subprocess.run(["cargo", "run", "--release", "--", "-vv", "vrps", "-o", "./output/ROA.csv", "-f", "csv"], stdout=fout, stderr=subprocess.DEVNULL)
    subprocess.run(["cp", "./output/ROV.json", "./output/ROVinit.json"])
while True:
    start = time.time()
    print("Starting ROV update, current time: " + datetime.fromtimestamp(start).strftime("%Y-%m-%d %H:%M:%S"))
    ROVout = "./output/ROVnew.json"
    fout = open(ROVout, "w")
    errout = "./output/ROV.err"
    ferr = open(errout, "w")
    subprocess.run(["cargo", "run", "--release", "--", "-vv", "vrps", "-o", "./output/ROA.csv", "-f", "csv"], stdout=fout, stderr=ferr)
    fname = "./output/diff/ROVdiff_" + str(int(time.time())) + ".json"
    subprocess.run(["python3", "ROVdiff.py", "./output/ROV.json", "./output/ROVnew.json", fname])
    # subprocess.run(["rm", "./output/ROV.json"])
    subprocess.run(["mv", "./output/ROVnew.json", "./output/ROV.json"])
    end = time.time()
    print("One ROV update finished, current time: " + datetime.fromtimestamp(end).strftime("%Y-%m-%d %H:%M:%S"))
    if end - start < INTERVAL:
        time.sleep(INTERVAL - (end - start))