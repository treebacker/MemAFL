#### 													Description

A Fuzz Tool Based On AFL, main source code are in `MemAFL/mm_metric`。

##### Features

* Pre-analysis

  Pre-analysis helps to find interesting strings which exits in some sensitive functions like `strcmp`。

  These interesting strings will be used in matation, to find potential bugs.

* Memory sensitive
  * MemAFL will record mem-operation in the execution path, will select the seed which does more mem-operetions.
  * MemAFL will record mem-functions in the execution path, such as `malloc`、`free` and so on.
  * 
* Reduce Hash collision
  * By Reducing redundant Instrumentation, memAFL can reduce hash collision.

##### Found CVEs

![](testcases\images\png\cve.png)



#### Dependence

* llvm\clang 7.0
* afl-2.52b

#### Install

* Compile AFl

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

