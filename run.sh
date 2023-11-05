mkdir output
cargo run --release -- --fresh -vv vrps -o ./output/ROA.csv -f csv > >(tee ./output/ROV.json) 2> >(tee ./output/ROV.err >&2)