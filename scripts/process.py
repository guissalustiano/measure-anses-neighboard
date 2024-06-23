import polars as pl

df = pl.read_csv("data.csv")
df.sort(["destination", "ttl"], descending=False).write_csv("data_sorted.csv")
