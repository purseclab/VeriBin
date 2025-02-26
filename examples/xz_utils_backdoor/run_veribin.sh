
python3 ../../src/veribin.py --original_path original/liblzma.so.5.5.99 --patched_path patched/liblzma.so.5.6.0  --func_addr_original 0x4144d4 --func_addr_patched 0x406ff4 --config_path config/config_preprocess.json --use_ida True --interactive True --debug False |& tee verify_result.log
