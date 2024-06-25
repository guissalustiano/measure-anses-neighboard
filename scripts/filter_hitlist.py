import polars as pl

df = pl.read_csv(
    "internet_address_hitlist_it106w-20231222.fsdb",
    has_header=False,
    new_columns=["hexip", "score", "ip"],
    separator="\t",
    comment_prefix="#",
)

df.filter(pl.col("score").gt(20)).select(pl.col("ip")).write_csv("ips.csv", include_header=False)
