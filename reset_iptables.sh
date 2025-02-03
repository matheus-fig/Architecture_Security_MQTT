#!/bin/bash

# Redefine as políticas padrão
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Remove todas as regras das tabelas filter, nat, mangle e raw
iptables -F     # Remove regras da tabela filter
iptables -X     # Remove chains personalizadas da tabela filter
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t raw -F
iptables -t raw -X

# Limpa contadores de pacotes
iptables -Z

# Exibe as regras atuais (que agora estão em branco, com políticas padrão)
echo "Regras do iptables redefinidas para o estado padrão:"
iptables -L -v -n