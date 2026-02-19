FROM hexpm/elixir:1.17.3-erlang-27.1.2-ubuntu-noble-20241015

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    iproute2 \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN mix local.hex --force && mix local.rebar --force

WORKDIR /app/vaisto_bpf
