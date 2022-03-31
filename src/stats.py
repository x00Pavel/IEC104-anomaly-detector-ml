from traceback import print_tb
import pandas as pd
from sys import argv
from os.path import exists, basename
from iec104Model import DATA_DIR
from matplotlib import pyplot as plt

assert len(argv) == 2, "No file specified"

file = argv[1] if exists(argv[1]) else f"{DATA_DIR}/{argv[1]}" 

data = pd.read_csv(file)
print(data)
chunks = []
intervals = data["interval"]
N = 100
for n in range(0, len(data), N):
    chunks.append(intervals.iloc[n:n+N].mean())

print(chunks)

plt.plot(range(0, len(chunks)), chunks)
plt.savefig(f"{DATA_DIR}/{basename(file)}.png")
