### 														

#### Dependence

* llvm\clang 7.0
* afl-2.52b

#### Install

* Compile AFl

  ```
  cd afl-2.52b
  make
  ```

* Compile mm_metric for MemAFL

  ```
  cd afl-2.52b/mm_metric
  make
  ```

#### How To Use

* compile target

  ```
  CC=~/path-to-afl-2.52b/mm_metric/afl-clang-fast CXX=~/path-to-afl-2.52b/mm_metric/afl-clang-fast ./configure
  make
  ```

* Start Fuzz

  ```
  ~/path-to-afl-2.52b/mm_metric/afl-fuzz -i input -o output -- ./target
  ```

* If you want to fuzz with`interesting string`, you will see a file `interesting.txt` in the compile path.

  you need copy the file to the fuzz work dir.
