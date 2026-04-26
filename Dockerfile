# base image
FROM python:3.13-slim

# update system and install nmap
RUN apt-get update && apt-get install -y nmap libcap2-bin && rm -rf /var/lib/apt/lists/*

# set nmap capabilities for non-root user
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/nmap

# create non-root user
RUN useradd -m -u 1000 mcp

# set working directory
WORKDIR /app

# install uv
RUN pip install --no-cache-dir uv

# copy project files
COPY . .

# uv install dependencies from pyproject.toml
RUN uv sync

# set permissions for mcp user
RUN chown -R mcp:mcp /app && chmod +x entrypoint.sh

# switch to non-root user
USER mcp

# start the MCP
EXPOSE 7777
CMD ["./entrypoint.sh"]