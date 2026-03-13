# VeriBin Source Code

## Directory Structure

- `veribin.py` — Main entry point for VeriBin.
- `veribin_func.py` — Function-level analysis logic.
- `veribin_hooks.py` — Hooking mechanisms for binary analysis.
- `veribin_path.py` — Path-related analysis utilities.
- `z3_syc.py` — Z3-based symbolic constraint checking.
- `load_config.py` — Configuration loading and parsing.
- `parse_spec_string.py` — Specification string parser.
- `ppc_helper.py` — PowerPC architecture helpers.
- `utils.py` — General utility functions.
- `preprocessor/` — Binary preprocessing (BinDiff, config generation, function extraction).
- `flirt_signatures/` — FLIRT signature files for library function identification.
- `helper_scripts/` — Helper scripts for dataset construction (e.g., FFmpeg patch builder).

## Usage

```bash
python src/veribin.py --original_path <path_to_the_original_binary> \
                      --patched_path <path_to_the_patched_binary> \
                      --func_addr_original <address_of_the_patched_function_in_the_original_binary> \
                      --func_addr_patched <address_of_the_patched_function_in_the_patched_binary> \
                      --config_path <path_to_a_config_file>
```

Additional optional settings:
```
  --debug               Enable debug mode (default: True)
  --interactive         Refine the analysis with analyst's response (default: True)
  --limitation          Max comparisons per path in C1 (default: 20)
  --merge_all           Merge all or split into path pairs (default: False)
  --update_assumption   Collect and replace offset changes (default: True)
  --use_ida             Use IDA to generate BinDiff (default: True)
  --graph_format {dot,png}  CFG plot format (default: dot)
  --is_ppc              PPC binary format (default: False)
```

For detailed examples, see the [examples directory](../examples/).
