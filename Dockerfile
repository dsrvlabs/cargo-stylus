# 빌드 스테이지
FROM --platform=linux/amd64 rust:1.80 as builder

# 빌드 인수 정의
ARG GIT_TAG

RUN apt-get update && apt-get install -y git

# Rust 타겟 추가
RUN rustup target add x86_64-unknown-linux-gnu

# 소스 코드 클론 및 특정 태그 체크아웃
RUN git clone https://github.com/dsrvlabs/cargo-stylus.git
WORKDIR /cargo-stylus
RUN git checkout ${GIT_TAG}

# 릴리즈 빌드 실행
RUN cargo build --release --manifest-path main/Cargo.toml

# 최종 이미지 스테이지
FROM --platform=linux/amd64 rust:1.80

# 빌드된 실행 파일을 최종 이미지로 복사
COPY --from=builder /cargo-stylus/target/release/cargo-stylus /usr/local/bin/cargo-stylus