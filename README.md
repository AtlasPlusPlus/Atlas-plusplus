Tested on IDA Pro 9.1, Python 3.14, Linux. IDA Pro 9+ and Python 3.12+ should also work, but older versions are not guaranteed.

Preparations:

1. [Finish environment setup](https://github.com/AtlasPlusPlus/env_setup).
1. Prepare IDA Pro. Edit `IDA_PATH` in `config.py`, and run `python config.py` to create work folders.
1. Install Python repirements. NOTE: the androguard package must use `dev` branch of our [fixed version](https://github.com/ChongChengAC/androguard/tree/dev) until all PRs are merged by upstream.

Run:

1. Put the target APK at `APK_PATH`.

2. Run NativeAnalyzer first and then JavaAnalyzer.
   ```shell
   cd .. # change directory to parent dir of Atlas++
   python -m Atlas-plusplus.NativeAnalyzer <apkname> [-l <lib>] # see `-h`
   python -m Atlas-plusplus.JavaAnalyzer <apkname> # see `-h`
   ```

### Semantic hints

JavaAnalyzer enables the `path`, `size`, and `array-len` semantic hints by
default. Use the single `--semantics` option to configure them:

```shell
# Default behavior: enable every semantic hint.
python -m Atlas-plusplus.JavaAnalyzer <apkname> --semantics all

# Disable every semantic hint.
python -m Atlas-plusplus.JavaAnalyzer <apkname> --semantics none

# Disable only path semantics.
python -m Atlas-plusplus.JavaAnalyzer <apkname> --semantics all,-path

# Enable exactly path and array-length semantics.
python -m Atlas-plusplus.JavaAnalyzer <apkname> --semantics path,array-len
```

The selected configuration is printed at startup. Generated variant directory
names also identify disabled hints, for example `0_all_on`, `1_path_off`, or
`2_path_off_size_off`.

Check `reproduce.txt` for reproduction.
