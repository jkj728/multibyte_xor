from distutils.core import setup, Extension

module = Extension("xordiffstream", sources = ["diff_stream.c"])

setup(name="PackageName",
        version = "1.0",
        description = "This is a package to calculate the difference stream for a bytearray using the XOR bitwise operator in C for efficiency improvement.",
        ext_modules = [module])

