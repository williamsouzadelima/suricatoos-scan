# --- Base image ------------------------------------------------------------
FROM ubuntu:22.04

ARG GECKOVERSION=0.33.0
ARG GOVERSION=1.21.5

RUN ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" != "arm64" ] && [ "${ARCH}" != "amd64" ]; then \
      echo "Suricatoos not supported, encountered unknown architecture: ${ARCH}" \
      && exit 1; \
    fi

# Labels and Credits
LABEL \
    name="Suricatoos" \
    author="Suricatoos <williamsouzadelima@gmail.com>" \
    description="Suricatoos is a automated pipeline of recon process, useful for information gathering during web application penetration testing."

# Environment Variables
ENV DEBIAN_FRONTEND="noninteractive" \
    DATABASE="postgres"
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV GOROOT="/usr/local/go"
ENV GOPATH=$HOME/go
ENV PATH="${PATH}:${GOROOT}/bin:${GOPATH}/bin"

# Install Python
RUN apt update -y && \
    apt install -y \
    python3.10 \
    python3-dev \
    python3-pip 

# Install essential packages
# apt-get update no MESMO layer do install: senão o índice fica preso ao layer
# anterior (cacheado) e .debs de patch superseded dão 404 ao rebuildar.
RUN apt update -y && apt install -y --no-install-recommends \
    build-essential \
    cmake \
    geoip-bin \
    geoip-database \
    gcc \
    gettext \
    git \
    libpq-dev \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpcap-dev \
    jq \
    netcat \
    nmap \
    x11-utils \
    xvfb \
    wget \
    curl \
    python3-netaddr \
    software-properties-common

# NÃO-FATAL: add-apt-repository contata o launchpad.net, que o buildkit deste box não
# alcança (timeout), quebrando builds limpos locais. É REDUNDANTE no build — o
# celery-entrypoint re-adiciona o pin do PPA e instala o firefox em RUNTIME. Best-effort:
# se o launchpad estiver acessível (ex.: CI) o PPA entra na imagem; senão o runtime cobre.
RUN add-apt-repository ppa:mozillateam/ppa || true

RUN ARCH=$(dpkg --print-architecture) \
    && curl -L https://go.dev/dl/go${GOVERSION}.linux-${ARCH}.tar.gz | tar -xzC /usr/local

RUN ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" = "arm64" ]; then \
      GECKOPATH="geckodriver-v${GECKOVERSION}-linux-aarch64.tar.gz"; \
    elif [ "${ARCH}" = "amd64" ]; then \
      GECKOPATH="geckodriver-v${GECKOVERSION}-linux64.tar.gz"; \
    fi \
    && wget https://github.com/mozilla/geckodriver/releases/download/v${GECKOVERSION}/${GECKOPATH} \
    && tar -xvf ${GECKOPATH} \
    && rm ${GECKOPATH} \
    && mv geckodriver /usr/bin

# Install Rust for orjson
RUN set -e; curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN pip3 install maturin

# Make directory for app
WORKDIR /usr/src/app

ENV GO111MODULE=on
# gitleaks is installed separately (in the && chain below) with its version
# embedded via the version.Version ldflag. Without -X, `gitleaks version` prints
# "version is set by build process" (no number), which makes the Tool Arsenal
# version lookup fail with "Invalid version lookup command".
RUN printf "\
    github.com/jaeles-project/gospider@latest\n\
    github.com/tomnomnom/gf@latest\n\
    github.com/tomnomnom/unfurl@latest\n\
    github.com/tomnomnom/waybackurls@latest\n\
    github.com/projectdiscovery/httpx/cmd/httpx@latest\n\
    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n\
    github.com/projectdiscovery/chaos-client/cmd/chaos@latest\n\
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n\
    github.com/projectdiscovery/naabu/v2/cmd/naabu@latest\n\
    github.com/hakluke/hakrawler@latest\n\
    github.com/lc/gau/v2/cmd/gau@latest\n\
    github.com/owasp-amass/amass/v3/...@latest\n\
    github.com/ffuf/ffuf@latest\n\
    github.com/projectdiscovery/tlsx/cmd/tlsx@latest\n\
    github.com/hahwul/dalfox/v2@latest\n\
    github.com/projectdiscovery/katana/cmd/katana@latest\n\
    github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest\n\
    github.com/sa7mon/s3scanner@latest\n" | \
    xargs -L1 go install -ldflags="-s -w" -v && \
    go install -ldflags="-s -w -X github.com/zricethezav/gitleaks/v8/version.Version=v8.30.1" -v github.com/zricethezav/gitleaks/v8@v8.30.1 && \
    rm -rf /go/pkg/* && rm -rf /root/.cache/go-build


# Update Nuclei and Nuclei-Templates
RUN nuclei -update-templates

# update chaos — NÃO-FATAL: `chaos -update` é um self-updater do binário que o `go install`
# acima já instalou na última versão; ele faz uma chamada NÃO-AUTENTICADA à API do GitHub que
# rate-limita (403) com frequência nos runners do CI, quebrando o build inteiro por nada
# (bloqueou PRs #35 e #38). Best-effort: se a atualização falhar, o chaos já instalado funciona.
RUN chaos -update || true

# Copy requirements (o `pip install -r` foi MOVIDO p/ o fim do Dockerfile — ver "App
# requirements LAST" — para o app reter autoridade de versão sobre as deps das OSINT tools).
COPY ./requirements.txt /tmp/requirements.txt
RUN pip3 install --upgrade setuptools==72.1.0

# --- OSINT/recon tools assados em BUILD-TIME ----------------------------------------------
# Antes eram clonados + pip-installados em runtime no celery-entrypoint.sh, o que rebaixava
# deps fixadas do app a cada boot do worker (dívida do A06/SQLAlchemy). Agora vivem na imagem.
# /usr/src/github deixou de ser volume nomeado (removido do docker-compose). --depth 1 minimiza
# a transferência. Pins idênticos ao entrypoint antigo (theHarvester 4.4.4, spiderfoot v4.0).
RUN set -eux; \
    mkdir -p /usr/src/github; \
    git clone --depth 1 https://github.com/aboul3la/Sublist3r /usr/src/github/Sublist3r; \
    git clone --depth 1 https://github.com/shmilylty/OneForAll /usr/src/github/OneForAll; \
    git clone --depth 1 https://github.com/FortyNorthSecurity/EyeWitness /usr/src/github/EyeWitness; \
    git clone --branch 4.4.4 --depth 1 https://github.com/laramies/theHarvester /usr/src/github/theHarvester; \
    git clone --branch v4.0 --depth 1 https://github.com/smicallef/spiderfoot /usr/src/github/spiderfoot; \
    git clone --depth 1 https://github.com/scipag/vulscan /usr/src/github/scipag_vulscan; \
    ln -sf /usr/src/github/scipag_vulscan /usr/share/nmap/scripts/vulscan; \
    git clone --depth 1 https://github.com/Tuhinshubhra/CMSeeK /usr/src/github/CMSeeK; \
    git clone --depth 1 https://github.com/UnaPibaGeek/ctfr /usr/src/github/ctfr; \
    git clone --depth 1 https://github.com/m3n0sd0n4ld/GooFuzz.git /usr/src/github/goofuzz; \
    chmod +x /usr/src/github/goofuzz/GooFuzz

# Deps Python das tools (podem rebaixar deps do app; o requirements.txt no FIM re-assevera).
# O sed tira o pin de pyyaml da spiderfoot (5.x não tem wheel p/ py3.10; 6.0.1 já funciona).
RUN set -eux; \
    sed -i '/^[[:space:]]*pyyaml/Id' /usr/src/github/spiderfoot/requirements.txt; \
    python3 -m pip install --no-cache-dir -r /usr/src/github/Sublist3r/requirements.txt; \
    python3 -m pip install --no-cache-dir -r /usr/src/github/OneForAll/requirements.txt; \
    python3 -m pip install --no-cache-dir -r /usr/src/github/theHarvester/requirements/base.txt; \
    python3 -m pip install --no-cache-dir -r /usr/src/github/spiderfoot/requirements.txt; \
    python3 -m pip install --no-cache-dir -r /usr/src/github/CMSeeK/requirements.txt; \
    python3 -m pip install --no-cache-dir h8mail; \
    python3 -m pip install --no-cache-dir tenacity==8.2.2

# OneForAll exige SQLAlchemy 1.3.x (crasha em 1.4); o app/langchain exige >=1.4.52. Isola a
# 1.3.22 em /opt/oneforall-sa (não-volume), carregada SÓ via PYTHONPATH=/opt/oneforall-sa na
# invocação do OneForAll (web/Suricatoos/tasks.py:603). NÃO trocar --target por pip install.
RUN pip install --target /opt/oneforall-sa --no-cache-dir "SQLAlchemy==1.3.22"

# install a Chrome/Chromium for EyeWitness (selenium_module.py is Chrome-only:
# webdriver.Chrome / find_chromedriver). ARCH-AWARE: Google publishes NO Linux/arm64
# Chrome build, and the previous unconditional amd64 .deb broke the arm64 image build
# (installing an amd64 .deb on arm64 fails). So:
#   * amd64  -> Google Chrome stable .deb (unchanged behaviour; MUST succeed — this is
#              the deployed architecture; the .deb pulls libnss3 + Chrome's runtime libs).
#   * arm64  -> best-effort Chromium from apt, NON-FATAL: screenshots are best-effort on
#              arm64 (not a deployed target), and a missing browser there must not fail
#              the image build. Ubuntu 22.04's chromium is a snap stub, so this may no-op.
RUN if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        wget -q -O /tmp/google-chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
        && (apt install -y /tmp/google-chrome.deb || (apt update -y && apt install -y /tmp/google-chrome.deb)) \
        && rm /tmp/google-chrome.deb; \
    else \
        echo "arm64/other: no Linux Google Chrome for $(dpkg --print-architecture); installing Chromium best-effort (screenshots best-effort; amd64 is the deployed target)" \
        && apt update -y \
        && (apt install -y chromium-browser chromium-chromedriver \
            || apt install -y chromium chromium-driver \
            || echo "WARNING: no Chromium package available on $(dpkg --print-architecture); image built without a browser"); \
    fi

# install eyewitness
# - psutil is a hard import in EyeWitness' modules/resource_monitor.py (added by the
#   2025 modernization); without it EyeWitness.py crashes on import -> no screenshots.
# - selenium 4.9.1 ships a Selenium Manager too old to resolve drivers for Chrome
#   115+ (the Chrome-for-Testing era); bump it so the driver auto-matches Chrome.
RUN pip3 install --no-cache-dir fuzzywuzzy \
    selenium==4.45.0 \
    python-Levenshtein \
    pyvirtualdisplay \
    netaddr \
    psutil

# App requirements LAST: re-assevera as versões fixadas do app por cima de qualquer downgrade
# que os installs das OSINT tools acima causaram (autoridade de versão). Substitui o
# `pip install -r requirements.txt` que o celery-entrypoint fazia a cada boot.
RUN pip3 install -r /tmp/requirements.txt --no-cache-dir

# Copy source code
COPY . /usr/src/app/

# A02-1 (belt-and-suspenders): never ship the Django SECRET_KEY inside the image.
# .dockerignore already excludes ./web/secret from the build context; this guards
# against a stale context/cache that still carries it. The live key is bind-mounted
# from ./web/secret (or sourced from SURICATOOS_SECRET_KEY) at runtime.
RUN rm -f /usr/src/app/secret
