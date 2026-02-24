init:
    uv venv --allow-existing --python 3.11
    source .venv/bin/activate
    uv pip install \
        ansible==12.3.0 \
        ansible-lint==26.1.1 \
        ruff==0.14.13 \
        antsibull-core==3.5.0
    ansible-galaxy collection install . --force

docs:
    ansible-galaxy collection install . --force
    mkdir -p .build/docs
    antsibull-docs sphinx-init --use-current --dest-dir .build/docs zupersero.tailscale
    uv pip install -r .build/docs/requirements.txt
    cd .build/docs && ./build.sh
    python3 -m http.server --directory .build/docs/build/html

ruff:
    .venv/bin/ruff check
