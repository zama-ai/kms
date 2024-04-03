mkdir -p coverage/reports
mkdir -p coverage/profdata
OUTPUT=$(RUSTFLAGS="-C instrument-coverage" cargo test -F slow_tests --lib --tests 2>&1| tee /dev/tty)
obj=$(echo $OUTPUT| grep "unittests src/lib.rs" | awk -F 'Running unittests src/lib.rs' '{print $2}'| cut -d "(" -f 2 | cut -d ")" -f 1)
id=$(echo $obj| awk -F 'distributed_decryption-' '{print $2}')
echo $obj
xcrun llvm-profdata merge -sparse default_*.profraw -o ddec.profdata
xcrun llvm-cov report --use-color --ignore-filename-regex='/.cargo/' --ignore-filename-regex='rustc/' --ignore-filename-regex='/target' --instr-profile=ddec.profdata --object $obj > coverage/reports/report$id.txt
xcrun llvm-cov export --ignore-filename-regex='/.cargo/' --ignore-filename-regex='rustc/' --ignore-filename-regex='/target' --format=lcov --instr-profile=ddec.profdata --object $obj > lcov.info
cp lcov.info coverage/coverage$id.lcov.info
rm -f *.profraw
mv ddec.profdata coverage/profdata/ddec$id.profdata
