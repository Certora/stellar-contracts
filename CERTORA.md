# Formal Verification Using Certora's Sunbeam Prover for Stellar Smart Contracts

We used Certora's Sunbeam prover to formally verify various parts of the code in this library. This document
explains how we have organized the work and how to run the prover, including helpful links. For a detailed summary of the work, please refer to the formal verification report.

## Installation
To install Certora's Sunbeam prover, see the documentation [here](https://docs.certora.com/en/latest/docs/sunbeam/installation.html). You can find a tutorial and troubleshooting details in our [documentation page](https://docs.certora.com/en/latest/docs/sunbeam/index.html).

## Project layout
- Within each package, we have included a new `confs` directory that
has the configuration files needed to run the verification jobs.

- For each component, we have also included a designated `specs` directory
that has the formal properties we wrote, any helpers, and mocks we used for verification.

- In the case of `vault`, we have created a 64 bit version (`vault_64`) to help scale formal verification. We also have introduced a 64 bit version of `math` which can be found here: `math/math_64`.

- For each package, we also have a `justfile` for compiling the code with the right version of the rust compiler and required feature flags. You can run `just build` to compile and generate the wasm bytecode.

- For each package, we also have a `certora_build.py` file that we use for running the verification jobs. You should rarely need to run this script manually.

## Looking at results and running the prover
- In each spec file, we have included a link to the verification job above each formal specification `#[rule]`. You can click on this link and see the results. Specifically, you can look at the `run.conf` file avialable in the link to see how exactly we ran the prover and what flags we used.

- We also have provided various `.conf` files to run the jobs. You can try them by running `certoraSorobanProver name.conf`. Note however that we sometimes run the rules individually and we do not include conf files for each individual rule separately. We recommend referring to the run links in the source code or the report for exact reproducibility.