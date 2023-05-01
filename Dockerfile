FROM rust:1.69-slim-buster
RUN apt-get update -y && apt-get install -y clang libclang-dev libpam0g-dev
