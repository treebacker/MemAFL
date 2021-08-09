#### 													Description

A Fuzz Tool Based On AFL, main source code are in `MemAFL/mm_metric`。

##### Features

* Pre-analysis

  Pre-analysis helps to find interesting strings which exits in some sensitive functions like `strcmp`。

  These interesting strings will be used in matation, to find potential bugs.

* Memory sensitive

  * MemAFL will record mem-operation in the execution path, will select the seed which does more mem-operetions.
  * MemAFL will record mem-functions in the execution path, such as `malloc`、`free` and so on.

* Sub function

  MemAFL record `call` times in the execution path，it  selects the seed which calls more sub functions to cover more paths in a fuzz loop.

* Reduce Hash collision

  * By Reducing redundant Instrumentation, memAFL can reduce hash collision.

##### Found CVEs

[![fGaxg0.png](https://z3.ax1x.com/2021/08/10/fGaxg0.png)](https://imgtu.com/i/fGaxg0)

#### Dependence

* llvm\clang 7.0
* afl-2.52b

#### Install

* Compile MemAFL

  ```
  cd MemAFL
  make
  ```

* Compile mm_metric for MemAFL

  ```
  cd MemAFL/mm_metric
  make
  ```

#### How To Use

* compile target

  ```
  CC=~/path-to-MemAFL/mm_metric/afl-clang-fast CXX=~/path-to-MemAFL/mm_metric/afl-clang-fast ./configure
  make
  ```

* Start Fuzz

  ```
  ~/path-to-MemAFL/mm_metric/afl-fuzz -i input -o output -- ./target
  ```

* If you want to fuzz with`interesting string`, you will see a file `interesting.txt` in the compile path.

  you need copy the file to the fuzz work dir.

