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

Check `reproduce.txt` for reproduction.
