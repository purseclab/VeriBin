
python3 ../../src/veribin.py --original_path original/gzip --patched_path patched/gzip  --func_addr_original 0x405810 --func_addr_patched 0x405810 --config_path config/config.json --use_ida True --interactive True --debug False |& tee verify_gzip.log