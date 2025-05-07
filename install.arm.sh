#!/bin/bash
# 포멧과 클린업
cargo fmt
cargo clippy --package cargo-stylus --package cargo-stylus-example

# 버전 목록 정의
VERSIONS=("v0.5.1" "v0.5.2" "v0.5.3" "v0.5.4" "v0.5.5" "v0.5.6" "v0.5.7" "v0.5.8" "v0.5.10" "v0.5.11")

# 각 버전 설치
for VERSION in "${VERSIONS[@]}"; do
  echo "Installing $VERSION-welldone..."
  git checkout "$VERSION-welldone"
  cargo install --path main --root ~/.cargo/"$VERSION-welldone"
done

# 설치된 경로 출력
echo "설치된 경로:"
for VERSION in "${VERSIONS[@]}"; do
  echo "$VERSION-welldone: ~/.cargo/$VERSION-welldone/bin/cargo-stylus"
done