# VMA_DESTROYER
Traverse a process's vma list and search for a specific ELF section

## Architecture
* `test/`: a simple test suite which contains an infinite loop
* `find_mm.c`: a kernel module which takes a parameter, `pid`, get the corresponding `task_struct`, tranverse its vma, and find the specific ELF section

## Usage
* Compile the kernel module
```
$> make
```
* Compile the test suite
```
$> cd test
$> make
```
* Launch a tester process
```
$> cd test
$> ./infinite_loop
Hello! I m an infinite loop
My PID: 12504
Tick, PID: 12504
Tock, PID: 12504
Tick, PID: 12504
```
* Insert the `find_mm` kernel module
```
# Insert the `find_mm` kernel module
$> sudo insmod find_mm.ko pid=XXX
# Check the kernel log
$> sudo dmesg
```
* clean
```
$> make clean
$> cd test; make clean
```
