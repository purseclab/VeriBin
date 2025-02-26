# VeriBin: Adaptive Verification of Patches at the Binary Level

This repository contains artifacts for the paper:
[VeriBin: Adaptive Verification of Patches at the Binary Level](https://github.com/purseclab/VeriBin/blob/main/VeriBin.pdf) accepted at the Network and Distributed System Security Symposium (NDSS 25)

## Citing this work

```
@inproceedings{wu2024veribin,
  title={VeriBin: Adaptive Verification of Patches at the Binary Level},
  author={Wu, Hongwei and Wu, Jianliang and Wu, Ruoyu and Sharma, Ayushi and Machiry, Aravind and Bianchi, Antonio},
  booktitle={Proceedings of the Network and Distributed System Security Symposium (NDSS)},
  year={2025}
}
```

## Directory Explanation
- `paper_experiments`: contains detailed tables showcasing the results from the experiments conducted in the paper.
- `examples`: example usage cases of VeriBin.
- `src`: source code of VeriBin.


## Installation
We recommand using docker to run VeriBin.
```
docker build -t veribin .
docker run --rm -it veribin
```

## Usage
For more detailed usage examples and a comprehensive explanation of VeriBin's internal workings and design choices, please refer to the [examples directory](examples).