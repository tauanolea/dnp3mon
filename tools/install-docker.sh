#!/bin/bash
# Instala Docker Engine + plugin compose pelo repositório oficial (Ubuntu ou Debian).
# Uso: sudo ./tools/install-docker.sh
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo "rode com sudo: sudo $0"
  exit 1
fi
. /etc/os-release
case "$ID" in
  ubuntu) CODENAME=${UBUNTU_CODENAME:-$VERSION_CODENAME} ;;
  debian) CODENAME=$VERSION_CODENAME ;;
  *) echo "distribuição $ID não suportada por este script; veja https://docs.docker.com/engine/install/"; exit 1 ;;
esac

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  echo "Docker já instalado: $(docker --version) / $(docker compose version)"
else
  apt-get update
  apt-get install -y ca-certificates curl
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$ID/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$ID $CODENAME stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
fi

# permite usar docker sem sudo (vale após sair e entrar de novo na sessão)
U=${SUDO_USER:-}
if [ -n "$U" ] && [ "$U" != "root" ]; then
  usermod -aG docker "$U"
  echo "Usuário $U adicionado ao grupo docker: saia e entre de novo na sessão (ou rode 'newgrp docker')."
fi
docker run --rm hello-world >/dev/null && echo "OK: Docker funcionando ($(docker --version))"
