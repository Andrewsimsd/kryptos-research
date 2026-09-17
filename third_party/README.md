# Pinned comparison programs

`bean-k4testing/gt.c`, `k4-testy.c`, `README.md` and `LICENSE` are unmodified files from
[RichardBean/k4testing](https://github.com/RichardBean/k4testing/tree/6a5e3cb200d5ab72a62bb7f5124b4fdf163faf8c),
commit `6a5e3cb200d5ab72a62bb7f5124b4fdf163faf8c`.
These files retain their upstream GPL-3.0 license, separate from this project's
MIT code. The experiment compiles and invokes `gt.c` as a separate comparison
program, only with arguments `10 5`; it is never linked into the Rust library.
The upstream program has historical C syntax and does not validate arbitrary
arguments. Its README describes a different command interface; this pinned
`gt.c` accepts base and primer length as two arguments.

Our constraint implementation derives graph equations from supplied cribs; it
does not copy the program's hard-coded list of K4 inequalities. The experiment
manifest pins its upstream file hashes.

`bean-statistics-harness.c` is a new GPL-3.0 adapter that includes the unchanged
`k4-testy.c`, renames its original `main`, and calls only its five measurement
functions. It accepts exactly 97 uppercase letters plus a newline per input
record and emits five integer statistics. The time-seeded original Monte Carlo
main is never run. The milestone-4 manifests pin both files; the adapter is
compiled and executed separately and never linked into the MIT Rust code.
