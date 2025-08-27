#!/bin/bash
# 포멧과 클린업
cargo fmt
cargo clippy --package cargo-stylus --package cargo-stylus-example

# 버전 목록 정의
VERSIONS=("v0.5.1" "v0.5.2" "v0.5.3" "v0.5.4" "v0.5.5" "v0.5.6" "v0.5.7" "v0.5.8" "v0.5.10" "v0.5.11" "v0.5.12" "v0.6.0" "v0.6.1" "v0.6.2" "v0.6.3")

# edition2024가 필요한 최신 버전들
EDITION2024_VERSIONS=("v0.6.2" "v0.6.3")

# Rustup 설치 확인 및 nightly 설치
if command -v rustup >/dev/null 2>&1; then
  echo "Installing nightly toolchain for edition2024 support..."
  rustup toolchain install nightly
else
  echo "Warning: rustup not found. Some versions may fail to install."
fi

# 각 버전 설치
for VERSION in "${VERSIONS[@]}"; do
  echo "Installing $VERSION-welldone..."
  git checkout "$VERSION-welldone"
  
  # edition2024가 필요한 버전인지 확인
  if [[ " ${EDITION2024_VERSIONS[@]} " =~ " ${VERSION} " ]]; then
    echo "Using nightly toolchain for $VERSION (requires edition2024)..."
    RUSTUP_TOOLCHAIN=nightly cargo install --path main --root ~/.cargo/"$VERSION-welldone"
  else
    cargo install --path main --root ~/.cargo/"$VERSION-welldone"
  fi
done

# 설치된 경로 출력
echo "설치된 경로:"
for VERSION in "${VERSIONS[@]}"; do
  echo "$VERSION-welldone: ~/.cargo/$VERSION-welldone/bin/cargo-stylus"
done