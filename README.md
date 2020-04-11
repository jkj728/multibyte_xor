# string-matching-commutative-ciphers

This repository is a python program written to allow for detection of patterns encrypted with the XOR operation with keys of arbitrary length. In order to detect an encrypted pattern, three elements are necessary: the cipher, a list of plaintexts being searched for and the key length (in bytes) they were encrypted with.

## Setup
In order to setup the python C extensions, run the following commands:
```
python3 setup.py build
python3 setup.py install
```

Then, you must copy the outputted object file `diff_stream.o` from the build directory and move it to the base directory of this repository. For example, if you run the python scripts on 64-bit Linux, then you will need to run `cp build/temp.linux-x86_64-3.6/diff_stream.o ./`. The subdirectory that begins with temp* will vary depending on the operating system.

Additionally, you must download the cipher into the local directory of this repository and create a plaintext file with a plaintext or patter per line. An example plaintext file:
```
Lorem
ipsum
dolor
```

## Running the program
To run the program, simple run the command:

```python3 multibyte_xor.py```
