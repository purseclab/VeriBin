## About `VeriBin`
`VeriBin` is a binary-level patch verification tool.
It compares a specific function in the original binary with its patched version in the patched binary, verifying the following four properties:
* **Condition 1: Input Space Restriction**: The function's valid input space should not be increased by the patch.

Consider, for instance, the following patch (`tidy` from the [`Micro-Patch Bench`](https://github.com/Aarno-Labs/micropatch-bench) dataset):
```C
+         if (doc->lexer == 0)
+             return;
```

This patch clearly "restricts" the input space accepted by the patched function by adding a check that, when true, leads to the termination of the function's execution. The rationale for checking this condition is that many security patches add additional checks on a function's input. Hence, these checks normally do not affect the intended functionality of the patched function. Conversely, increasing the function's input space may lead to unexpected behavior in the patched binary.

* **Condition 2: Global Writes Equivalence**: Global memory writes must remain the same.

By checking this condition, `VeriBin` verifies that the patch does not affect how the patched function modifies global variables.
The rationale of this check is that we do not expect the patch to affect how the patched function modifies the state of variables outside the patched function itself.

* **Condition 3: Return Value Equivalence**: The return value must remain the same.

By checking this condition, `VeriBin` verifies that the patch does not affect how the patched function's return value is computed.
The rationale of this check is that we do not expect the patch to affect how the patched function "communicates" with other parts of the program.

* **Condition 4: Called Functions Arguments Equivalence**: Function arguments of any called function must remain the same.

By checking this condition, `VeriBin` verifies that the patched function calls the same functions, using the same arguments.
The rationale of this check is that we do not expect the patch to affect how the patched function "interacts" with other parts of the program.

All these 4 properties are only evaluated on **Valid Exit Paths**, i.e., paths that do not lead to the function's termination due to an error condition..

#### Adaptive Verification

If all four conditions are verified, `VeriBin` determines the patch as `Safe to Apply`.

Conversely, if `VeriBin` detects any potential violation of these properties, the analyst is notified, who can then either accept or deny the encountered violation. In general, the analyst should accept all the violations expected to be caused by the intended behavior of the patch.

## Preparation Steps for `VeriBin`

### Locating potential patch affected functions
`VeriBin` requires a pair of target function addresses in the original and patched binaries.
A helper script using BinDiff identifies non-perfectly matched functions:
```
python3 src/preprocessor/locate_diffing_functions.py --original_path <original_binary_path> --patched_path <patched_binary_path>
```
Accurately identifying patch-affected functions is outside the scope of our tool. Analysts are expected to put in extra effort when the BinDiff result is empty or inaccurate.

### Generating Configuration Files for `VeriBin`

For each analysis, `VeriBin` requires a specific configuration file in the `json` format.

The following is a commented version of the configuration file for [`Tidy`](tidy-cve-2012-0781/config/config.json):
```
{
  # This is a list of function names and corresponding addresses in the original and in the patched binary
  # In general, VeriBin needs to know the names of all the functions called by the original function as well as the patched function

  "symbol_table": {
    "original": {
      "0x418673": "prvTidyApparentVersion",
      "0x4186da": "prvTidyHTMLVersionNameFromCode",
      "0x4186fc": "prvTidyWarnMissingSIInEmittedDocType",
      "0x427ad2": "message",
      "0x429f20": "prvTidyReportMarkupVersion",
      "0x42ad64": "prvTidy_cfgGetBool"
    },
    "patched": {
      "0x418673": "prvTidyApparentVersion",
      "0x4186da": "prvTidyHTMLVersionNameFromCode",
      "0x4186fc": "prvTidyWarnMissingSIInEmittedDocType",
      "0x427ad2": "message",
      "0x429f20": "prvTidyReportMarkupVersion",
      "0x42ad78": "prvTidy_cfgGetBool"
    }
  },

# This dictionary provides extra information about the above functions
# 	num_of_args: the number of arguments a function takes
# 	output_args_index: which of these arguments (if any) are used as pointers to store data by the called functions
#   return_value_used: whether the function has a return value or not (i.e., returning void)

  "func_info_map": {
    "prvTidyApparentVersion": {
      "num_of_args": 1,
      "output_args_index": [
        0
      ],
      "return_value_used": true
    },
    "prvTidyHTMLVersionNameFromCode": {
      "num_of_args": 2,
      "return_value_used": true
    },
    "prvTidyWarnMissingSIInEmittedDocType": {
      "num_of_args": 1,
      "output_args_index": [
        0
      ],
      "return_value_used": true
    },
    ...
  },

# Exit_edges are edges in the control flow graph that, when executed, lead to the function's termination due to an error condition.
# If VeriBin didn't automatically mark certain error-handling exit paths as invalid, you can manually add the corresponding exit edges here. Any execution path visiting these exit edges will be considered invalid.

  "exit_edges": {
    "original": [],
    "patched": []
  },
}
```
The configuration file for `VeriBin` is generated through the following processes:
- Initiate a pre-processing step by executing a helper script. This script extracts essential data such as the symbol table, function information map, and matching functions.
```
python3 src/preprocessor/generate_config_for_single_file.py --original_path <original_binary_path> --patched_path <patched_binary_path>  --func_addr_original <func_addr_original> --func_addr_patched <func_addr_patched> --version <ida,bindiff,angr> --out_dir <output_dir_path> --force_run <True or False>
```

- Analysts are responsible for reviewing and correcting any inaccuracies in function signatures or symbol names and for adding exit-edge information as necessary.

## Running `VeriBin`

To run `VeriBin` use:

`python src/veribin.py --original_path <path_to_the_original_binary> --patched_path <path_to_the_patched_binary>  --func_addr_original <address_of_the_patched_function_in_the_original_binary> --func_addr_patched <address_of_the_patched_function_in_the_patched_binary> --config_path <path_to_a_config_file>`

Additional optional settings:
```
  --debug DEBUG         Enable debug mode or not (default: True)
  --interactive INTERACTIVE
                        Refine the analysis with analyst's response or not (default: True)
  --limitation LIMITATION
                        The maximum number of allowed comparisons per path in C1 (default: 20)
  --merge_all MERGE_ALL
                        Comparison strategy: merge all or split into path pairs (default: False)
  --update_assumption UPDATE_ASSUMPTION
                        Whether to collect and replace offset changes or not. (default: True)
  --use_ida USE_IDA     Whether to use IDA to generate BinDiff or not. (default: True)
  --graph_format {dot,png}
                        The format for plotting out the CFGs. (default: dot)
  --is_ppc IS_PPC       Whether the binary is special PPC format or not. (default: False)
```

## Examples
We provide several case studies that demonstrate the effectiveness of our approach in various scenarios. Each example includes a detailed description of the analysis process and the insights gained.

- [Tidy CVE-2012-0781 Example](tidy-cve-2012-0781/README.md): This example involves a minimal patch that adds a safety check to prevent potential vulnerabilities. View Details

- [XZ Utils Backdoor Example](xz_utils_backdoor/README.md): This example analyzes a sophisticated backdoor introduced into the XZ Utils project, highlighting the importance of binary-level verification. View Details

- [GZip Example](gzip-a1d3d4019d-f17cbd13a1/README.md): Demonstrates adaptive verification in action, where a patch that technically violates safe-to-apply properties can still be deemed safe-to-apply through analyst intervention.
