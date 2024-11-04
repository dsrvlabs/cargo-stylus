#!/bin/bash
# 포멧과 클린업
cargo fmt
cargo clippy --package cargo-stylus --package cargo-stylus-example

# v0.5.1 설치
git checkout v0.5.1-welldone
cargo install --path main --root ~/.cargo/v0.5.1-welldone

# v0.5.2 설치
git checkout v0.5.2-welldone
cargo install --path main --root ~/.cargo/v0.5.2-welldone

# 설치된 경로 출력
echo "v0.5.1-welldone: ~/.cargo/v0.5.1-welldone/bin/cargo-stylus"
echo "v0.5.2-welldone: ~/.cargo/v0.5.2-welldone/bin/cargo-stylus"