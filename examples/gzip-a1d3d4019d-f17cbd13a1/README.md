## VeriBin: GZip Example
This example demonstrates the analysis of a patch in GZip, highlighting a scenario where adaptive verification can be applied to potentially accept a patch that initially violates a safe-to-apply condition.
This example is sourced from the [`Micro-Patch Bench`](https://github.com/Aarno-Labs/micropatch-bench).

### Patch Description
The patch introduces a seemingly innocuous change: initializing a global variable `ifd` to `0` at the beginning of the `treat_file` function.
```C
 local void treat_file(iname)
     char *iname;
 {
+    //prophet generated patch
+    ifd = (0);
     /* Accept "-" as synonym for stdin */
     if (strequ(iname, "-")) {
 	int cflag = to_stdout;
```
While this patch technically violates condition 2 (Global Writes Equivalence) by performing an extra write to the global variable ifd, it presents an opportunity to explore adaptive verification.
This approach allows an analyst to potentially accept the modification if they deem the overall patch safe-to-apply, despite the strict violation.
Adaptive verification recognizes that some changes, while technically violating a condition, may still be considered safe within the broader context of the patch's intended behavior and the system's overall functionality.

## Running
### View the Patch
To examine the differences between the original and patched versions:
```bash
cd examples/gzip-a1d3d4019d-f17cbd13a1
cat source/gzip.c.diff
```

### Locate Patch-Affected Functions
To identify the functions affected by the patch:
```bash
./locate_diffing_funcs.sh
```
The result from `BinDiff` shows that function `treat_file` at address `0x405810` is potentially affected by the patch.
### Generate Configuration File
To create the initial configuration file:
```bash
./generate_config_from_binary.sh
```

### Verify the Patch
To run `VeriBin` and verify the safety of the patch:
```bash
./run_veribin.sh
```
In this example, `VeriBin` identifies the extra write to the global variable and interacts with the analyst.
If the analyst considers this modification to be an expected or acceptable part of the intended patch behavior and chooses to accept the associated StA (Safe-to-Apply) property violation, VeriBin will integrate this information into its analysis and, after further checks, may conclude that the patch is ultimately safe to apply.