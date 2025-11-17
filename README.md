# Python Library Fuzzers

This repository contains the fuzzer definitions, seed corpora,
and dictionaries used by [OSS-Fuzz](https://github.com/google/oss-fuzz) to fuzz-test Python standard library modules.

## Getting Started

Read the [getting started](https://google.github.io/oss-fuzz/getting-started/)
guide for OSS-Fuzz to learn about the [architecture of the fuzzer](https://google.github.io/oss-fuzz/architecture/)
and the necessary dependencies for local development (Docker, Python).

## Architecture

There are four components of the [OSS-Fuzz architecture](https://google.github.io/oss-fuzz/architecture/)
hosted in this repository. Other components of
the OSS-Fuzz architecture are hosted in other repositories.

Components that are hosted in this repository:

* Fuzz target definitions. These are typically `.py` files that are bootstrapped
  into binaries by `fuzzer.cpp` and `Makefile`.
* Fuzz seed corpora (`corp-*`): These files contain "starting points" byte
  sequences that the fuzzer can use to get results quicker than random bytes.
* Fuzz dictionaries (`*.dict`): These files contain possible byte sequences that
  the fuzzer can use when mutating input sequences.
* Coverage header file (`python_coverage.h`): This file is compiled with CPython
  so that line coverage is tracked over time as the fuzzer executes.

Components that are hosted elsewhere:

* [Project configuration](https://github.com/google/oss-fuzz/tree/master/projects/python3-libraries): 
  This component controls the OSS-Fuzz project definition, maintainers.
* [Fuzzer image configuration](https://github.com/google/oss-fuzz/tree/master/projects/python3-libraries):
  `Dockerfile` and `build.sh` describe how the fuzzer
  image is built and what fuzz targets are executed by OSS-Fuzz.

When you create a new fuzz target **don't forget to add the target to the fuzzer image**
so that the fuzz target is executed by OSS-Fuzz.

## Local development

To do develop locally with OSS-Fuzz you need to fork and clone the
following repositories:

* https://github.com/google/oss-fuzz
* https://github.com/python/library-fuzzers
* https://github.com/python/cpython

After cloning forks of these repositories, move into the `oss-fuzz`
repository and run the following to build the base and fuzzer image:

```sh
python infra/helper.py build_image python3-libraries
python infra/helper.py build_fuzzers python3-libraries
```

Once this succeeds you have the proper toolset to locally develop fuzzers.
You can run fuzz targets using the same helper script:

```sh
python infra/helper.py run_fuzzer python3-libraries fuzzer-email
```

This will run the fuzzer indefinitely, so stop the fuzzer whenever
you've confirmed that it works.
Now we need to point the `oss-fuzz` repository to our own forks to start
local development.

Modify the `projects/python3-libraries/Dockerfile` file `git clone` lines
to point to your own forks (example below using `sethmlarson`). It's recommended
to use a branch on forks instead of `main`, so the example below also uses
`--branch fork-branch` which you can change to your own branch depending on
which repository you are modifying during development.

```diff
-RUN git clone https://github.com/python/cpython.git cpython
-RUN git clone --depth 1 https://github.com/python/library-fuzzers.git
+RUN git clone --depth 1 --branch fork-branch https://github.com/sethmlarson/cpython.git cpython
+RUN git clone --depth 1 --branch fork-branch https://github.com/sethmlarson/python-library-fuzzers.git
```

After this you can now re-run the `python infra/helper.py` commands to rebuild the image and fuzzers
using the fork repositories instead. From here local development proceeds through pushing commits
to your fork branches, rebuilding the image and fuzzers, and then running the fuzzers.
