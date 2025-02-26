## VeriBin: XZ_Utils Backdoor Example
This example demonstrates the analysis of the recently discovered XZ Utils backdoor (CVE-2024-3094), which was maliciously introduced into the XZ Utils project via an obfuscated script during compilation.
## Running the Analysis
### Locate Patch-Affected Functions
To identify the functions affected by the backdoor:
```bash
./locate_diffing_funcs.sh
```
The result from `BinDiff` shows a list of candidate function pairs.
In this demonstration, we focus on the function `lzma_crc64` at addresses `0x4144d0` (original binary) and `0x406ff0` (patched binary).

### Generate Configuration File
To create the configuration file:
```bash
./generate_config_from_binary.sh
```

### Verify the Patch
To run `VeriBin` and verify the safety of the patch:
```bash
./run_veribin.sh
```
In this example, `VeriBin` detects an assembly instruction `cpuid` is replaced by a function call `get_cpuid`, and determines that this patch is not safe-to-apply.
This case study highlights the need to employ binary-level verification, even when their source code is available.