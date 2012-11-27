# Usage

To build, just run `make`. The `make` uses `waf` to figure out dependencies for the executables. The executable is located in the bin directory. To run it, you need to include the path to necessary netfilter libraries. This can be done by including that when calling the execute like this:

```
sudo LD_LIBRARY_PATH=/usr/local/lib bin/wifu
```
