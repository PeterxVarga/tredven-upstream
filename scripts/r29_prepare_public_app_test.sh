#!/usr/bin/env bash
# Test-only: fetch exactly one public educational sample and build a private
# rootless Podman image. No real credentials, no deployment, no registry push.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
out="$repo/output/r29-public-app-fixture"
source="$out/upstream-paul"
context="$out/build-context"
commit="417de5b4c3e2741853944fbf97a9988de48d647d"
image="localhost/tredven-r29-public-fastapi-worker-redis:417de5b"
test "$(id -u)" -ne 0
test "$(podman info --format '{{.Host.Security.Rootless}}')" = true
test ! -e "$out"
install -d -m 700 "$out" "$source" "$context" "$context/app"
git -C "$source" init -q
git -C "$source" remote add origin https://github.com/paulohsz/FastAPI-Celery-Docker.git
GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 git -C "$source" -c core.hooksPath=/dev/null fetch --depth=1 origin "$commit"
git -C "$source" -c core.hooksPath=/dev/null checkout --quiet --detach "$commit"
test "$(git -C "$source" rev-parse HEAD)" = "$commit"
test -z "$(git -C "$source" status --porcelain --untracked-files=all)"
# The source code remains only in ignored output/; never distribute or commit it.
cp -a "$source/backend/app/." "$context/app/"
cp "$source/backend/requirements.txt" "$context/requirements.txt"
# A private git clone has restrictive mode bits; allow only read/execute on
# this disposable build copy, not new host/root privileges.
chmod -R a+rX "$context/app"
cat > "$context/Containerfile" <<'EOF'
FROM docker.io/library/python:3.13-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir --only-binary=:all: -r requirements.txt
COPY app /app/app
USER 65532:65532
ENTRYPOINT ["python"]
CMD ["-c", "print('R29 explicit command required')"]
EOF
cat > "$context/Containerfile.redis" <<'EOF'
FROM localhost/tredven-r29-public-fastapi-worker:417de5b
USER 0:0
# Kombu 5.7 requires redis-py >=6.1; package 'packaging' is an extra runtime dep.
RUN python -m pip install --no-cache-dir --only-binary=:all: redis==6.1.0 packaging==25.0
USER 65532:65532
EOF
# Only public downloads before isolated test runtime. Verify exact downloaded
# image IDs from Podman inspect and report; never enable host ports or auth.
podman pull docker.io/library/python:3.13-slim
podman pull docker.io/library/postgres:16
podman pull docker.io/library/postgres:17
podman pull docker.io/library/redis:7-alpine
podman build --pull=never --network=pasta --layers -f "$context/Containerfile" \
  -t localhost/tredven-r29-public-fastapi-worker:417de5b "$context"
podman build --pull=never --network=pasta --layers -f "$context/Containerfile.redis" \
  -t "$image" "$context"
# Check the actual upstream app and Celery transport load as a non-root user.
podman run --rm --pull=never --network=none \
  -e DATABASE_URL=postgresql+asyncpg://postgres@db:5432/appdb \
  -e DATABASE_URL_SYNC=postgresql+psycopg2://postgres@db:5432/appdb \
  -e RABBITMQ_URL=redis://broker:6379/0 \
  -e CELERY_BROKER_URL=redis://broker:6379/0 \
  -e CELERY_RESULT_BACKEND=redis://broker:6379/1 \
  --security-opt=no-new-privileges "$image" \
  -c 'import app.main,kombu.transport.redis,os;assert os.getuid()!=0;print("PINNED_REAL_APPLICATION_READY")'
echo "PUBLIC_APP_SOURCE_COMMIT=$commit"
podman image inspect "$image" --format 'PRIVATE_LOCAL_TEST_IMAGE_ID={{.Id}}'
echo "R29_OWNER_PRIVATE_BUILD_READY_NOT_DISTRIBUTED"
