# pk11setpasswordfuncwrapper
The shared library for automatic PK11 password substitution

## Compile command
gcc -Wall -fPIC -shared -o libpk11setpasswordfuncwrapper.so pk11setpasswordfuncwrapper.c -ldl

## Usage example
Add to the /opt/google/chrome/google-chrome, before execs at the end of the script:
```
export PK11_HARDCODED_KL_PASSWORD='MyTokenSecurePin'
export LD_PRELOAD="/path/to/libpk11setpasswordfuncwrapper.so"
```
