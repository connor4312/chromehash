#-------------------------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See https://go.microsoft.com/fwlink/?linkid=2090316 for license information.
#-------------------------------------------------------------------------------------------------------------

# To fully customize the contents of this image, use the following Dockerfile instead:
# https://github.com/microsoft/vscode-dev-containers/tree/v0.100.0/containers/ubuntu-18.04-git/.devcontainer/Dockerfile
FROM mcr.microsoft.com/vscode/devcontainers/javascript-node:12

ENV PATH /root/.cargo/bin:/root/emsdk/upstream/bin:$PATH

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN cargo install wasm-pack

# Install emsdk
RUN cd /root \
  && git clone https://github.com/emscripten-core/emsdk.git \
  && cd emsdk \
  && ./emsdk install latest


# Install benchmark util
RUN npm i -g @c4312/matcha
