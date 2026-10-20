FROM rust:1.92-slim-bookworm AS cli
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/inline_main.rs src/inline_main.rs
RUN cargo build --locked --release --bin ghidra

FROM eclipse-temurin:21-jdk-noble
ARG GHIDRA_VERSION=12.1.2
ARG GHIDRA_DATE=20260605
ARG GHIDRA_SHA256=b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv curl unzip libxtst6 libxi6 libxrender1 && rm -rf /var/lib/apt/lists/*
RUN curl -fL --retry 3 "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" -o /tmp/ghidra.zip \
    && echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra \
    && rm /tmp/ghidra.zip
RUN python3 -m venv /opt/pyghidra && /opt/pyghidra/bin/pip install --no-cache-dir --no-index --find-links /opt/ghidra/Ghidra/Features/PyGhidra/pypkg/dist pyghidra==3.1.0
COPY --from=cli /build/target/release/ghidra /usr/local/bin/ghidra
COPY python /app/inline
ENV PYTHONPATH=/app/inline GHIDRA_INSTALL_DIR=/opt/ghidra PYTHONUNBUFFERED=1 HOME=/tmp JAVA_TOOL_OPTIONS=-Duser.home=/tmp
USER 1000:1000
EXPOSE 8089
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 CMD curl -fsS http://localhost:8089/health || exit 1
STOPSIGNAL SIGTERM
ENTRYPOINT ["/opt/pyghidra/bin/python", "-m", "ghidra_inline.server"]
CMD ["--host", "0.0.0.0", "--port", "8089"]
