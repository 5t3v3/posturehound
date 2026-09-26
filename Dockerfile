# PostureHound - containerised read-only Azure identity posture scanner.
#
# Pinned to Python 3.12 (NOT 3.14) so the embedded Kùzu Cypher backend wheel
# installs and the attack-graph Cypher engine is available in the container,
# matching the production VM. The engine still falls back to networkx if absent.
FROM python:3.12-slim

# Native libraries WeasyPrint needs to render the shareable PDF report
# (pango / cairo / harfbuzz / gdk-pixbuf). Without them the app still runs and
# serves a printable HTML report instead - so this is best-effort but included
# so PDF export works out of the box. fonts-dejavu-core gives the PDF real glyphs.
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpango-1.0-0 libpangocairo-1.0-0 libpangoft2-1.0-0 \
      libharfbuzz0b libgdk-pixbuf-2.0-0 libffi8 libcairo2 \
      fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    PH_DATA_DIR=/data \
    PORT=8000 \
    WORKERS=1

WORKDIR /app

# Install dependencies first so this layer is cached across source edits.
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Application source only (the .dockerignore keeps the venv, git, data and
# scratch out of the build context). Includes the vendored static assets.
COPY src ./src

# Scan history, settings, custom Tier-0 and saved queries live here - mount a
# volume so they survive container recreation.
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8000

# Bind 0.0.0.0 INSIDE the container; the host port is published (and locked to
# localhost) in docker-compose.yml.
CMD ["sh","-c","python -m uvicorn posturehound.api:app --host 0.0.0.0 --port ${PORT} --workers ${WORKERS}"]
