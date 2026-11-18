# dnp3mon: monitor passivo de DNP3 para o ADMS

Recebe o espelhamento (SPAN/TAP) da rede entre os FEPs do ADMS e as RTUs e faz o seguinte:
- decodifica 100% dos pacotes DNP3: enlace com CRC, transporte e aplicação, com todos os objetos de uso comum;
- correlaciona pedido↔resposta, comandos e pontos;
- grava indicadores por RTU a cada minuto, mensagens, valores de pontos, comandos e eventos no ClickHouse;
- guarda o tráfego bruto em PCAP rotativo, que é a fonte da verdade e permite reprocessar tudo;
- expõe dashboards e alertas no Grafana, um tail ao vivo no navegador e o recorte de PCAP por RTU.

```
 RTUs (4000 DNP3 / 90 IEC104)
         │
 [switch dos FEPs] ──SPAN/TAP──► NIC de captura (sem IP)
                                    │
                         ┌──────────▼──────────┐
                         │ dnp3mon (Go)        │──► PCAP rotativo (30+ dias, gzip)
                         │ AF_PACKET → TCP →   │──► API :8080 (tail ao vivo SSE, RTUs, recorte PCAP, /metrics)
                         │ enlace → transporte │
                         │ → aplicação → motor │
                         └──────────┬──────────┘
                                    │ lotes JSON (HTTP), spool em disco se o banco cair
                             ┌──────▼──────┐        ┌──────────────┐
                             │ ClickHouse  │◄───────│ Grafana      │ dashboards + alertas
                             └─────────────┘        └──────────────┘
```

## O que é medido

**Por RTU, a cada minuto** (`dnp3.rtu_stats_1m`, mais o agregado por hora `rtu_stats_1h` guardado por 2 anos):

| Grupo | Indicadores |
|---|---|
| Estado | online/offline, IIN atual, master (FEP) ativo |
| TCP | pacotes e bytes por sentido, SYN, SYN repetido, conexões abertas e falhas, resets, FIN, retransmissões, **lacunas de captura**, keep-alive, janela zero, RTT (dado do master → ACK da RTU) |
| Enlace | frames, **erros de CRC**, bytes de lixo, REQUEST_LINK_STATUS enviados, respondidos e sem resposta, latência do link status, RESET_LINK, NACK, retransmissões de enlace (FCB), erros de transporte |
| Aplicação | requisições, respostas, não solicitadas (inclusive nulas), confirmações, **timeouts**, **retentativas**, respostas atrasadas ou inesperadas, erros de parse, pedidos rejeitados (IIN 2.0–2.2), não solicitadas repetidas, confirmações faltando, tempo de resposta (soma, contagem e máximo) |
| Varredura | integridades pedidas e concluídas, varreduras de eventos, sincronismos de hora, FCs sensíveis |
| IIN | respostas com RESTART, NEED_TIME, LOCAL, TROUBLE, EVENT_OVERFLOW, CONFIG_CORRUPT |
| Comandos | total, sucesso, falha |
| Dados | eventos de pontos, mudanças de estáticos, mudanças binárias, qualidade ruim, **eventos perdidos (suspeita)**, **chattering**, carimbo de tempo inválido, atraso dos eventos (mín., médio e máx.), que revela relógio errado |

**Por ocorrência:**
- `dnp3.messages`: cada APDU e frame de enlace decodificado, com resumo estilo Wireshark, tempo de resposta, retry e arquivo PCAP.
- `dnp3.points`: eventos e mudanças de estáticos, com o carimbo de tempo da RTU.
- `dnp3.point_last`: último valor de cada ponto.
- `dnp3.commands`: ciclo de vida completo do comando:
  - SELECT → OPERATE → resposta;
  - status do CROB (LOCAL, HARDWARE_ERROR, NO_SELECT…), timeout, eco divergente;
  - **retorno de estado**: o primeiro binário que mudou depois do comando e em quanto tempo.
- `dnp3.events`: queda e volta da comunicação, transições de IIN, failover de FEP, master não autorizado, FC sensível (restart, arquivo, disable unsolicited), CRC, chattering, evento perdido, hora escrita pelo master, conexões TCP.

A chave do equipamento é **`ip:porta` da RTU**, por exemplo `10.20.3.10:20000`. Se a RTU for cliente TCP, com porta efêmera, a chave passa a ser só o IP.

## Dimensionamento (medido com o simulador)

Teste: 4.000 RTUs, 3 horas, cerca de 196 kbit/s de DNP3. Os números abaixo foram extrapolados para os **350 kbit/s DNP3 + 150 kbit/s IEC 104** do ambiente real.

| Item | Medido | Projeção real |
|---|---|---|
| Decodificador | 3,5 milhões de pacotes em 51 s num núcleo (cerca de 67 mil pacotes/s) | tráfego real de ~600 pacotes/s: **< 1% de um núcleo** |
| PCAP bruto (gzip) | 321 MB por 3 h sem compressão (46% com gzip) | **~3 GB/dia**: 30 dias ≈ 90 GB, 90 dias ≈ 270 GB |
| `messages` | 19 B/linha | ~0,5 GB/dia: 90 dias ≈ 45 GB |
| `rtu_stats_1m` | 47 B/linha (4.000 linhas/min) | ~0,26 GB/dia: 90 dias ≈ 23 GB |
| `points` | 13 B/linha | ~0,1 GB/dia: 90 dias ≈ 9 GB (multiplique por 3–5 se houver muito mais pontos ou deadband apertada) |
| `rtu_stats_1h` | | 2 anos ≈ 13 GB |

**VM recomendada:**
- **8 vCPU** (4 bastam hoje);
- **32 GB de RAM** (mínimo 16);
- disco do sistema de 50 GB;
- **disco de dados SSD de 1 TB** (PCAP de 90 dias + banco + folga; para só 30 dias de PCAP, 500 GB bastam);
- placas de rede: 1 de gerência + 1 de captura por origem de espelhamento. Com 4 FEPs redundantes, garanta que o SPAN cubra **todos** os FEPs, inclusive os de reserva.

**Em VMware**, o espelhamento precisa chegar a uma placa física dedicada do host. Crie um vSwitch ou port group só para ela com **Promiscuous mode = Accept** (e VLAN 4095 se vier tronco), ou use passthrough PCI da placa. Se usar SPAN de duas origens que se sobrepõem, o dnp3mon descarta pacotes duplicados (janela de 30 ms).

## Instalação na VM

1. Pré-requisitos: Linux com Docker e o plugin compose. A interface de captura deve estar **sem IP**; o dnp3mon a coloca em modo promíscuo.
2. Copie o projeto. Se a VM não tiver internet, gere o pacote aqui com `tools/bundle.sh`; ele leva as imagens e o plugin do Grafana.
3. Configure:
   ```bash
   cd dnp3mon/deploy
   cp .env.example .env      # interfaces, senhas, DATA_DIR, IPs dos FEPs
   sudo ./setup.sh           # cria os diretórios e acerta as permissões (precisa de root)
   docker compose up -d
   ```
4. Acesse:
   - Grafana em `http://VM:3000`: pasta **DNP3**, com 5 dashboards e 8 alertas.
   - Tail ao vivo em `http://VM:8080`.
   - Em cada dashboard, informe a URL da API (`http://VM:8080`) na caixa *API dnp3mon* para os links de tráfego ao vivo e de baixar PCAP. Salve o dashboard para fixar.
5. Alertas: renomeie `deploy/grafana/provisioning/alerting/contato.yaml.exemplo` para `contato.yaml` e coloque e-mail ou webhook. Para e-mail, configure `GF_SMTP_*`.

**Teste sem o SPAN** (valida a instalação). Use uma interface dummy ou veth de laboratório:
```bash
docker compose exec dnp3mon dnp3sim -rtus 200 -dur 10m -o /data/teste.pcap
docker compose exec dnp3mon dnp3replay -i <iface_de_teste> /data/teste.pcap
```

## Uso no dia a dia

| Quero… | Onde |
|---|---|
| Ver a saúde da frota | Grafana › *DNP3 · Visão geral da frota*: online/offline, disponibilidade, piores RTUs, IIN ativos, eventos críticos, FEP ativo |
| Investigar uma RTU | Clique na RTU (vai para *Detalhe da RTU*): estado, tempos de resposta por requisição, mensagens decodificadas, pontos e gráfico dos selecionados, comandos, eventos, relógio, período de integridade |
| Comandos executados e falhados | *DNP3 · Comandos*: taxa de sucesso, falhas por status (LOCAL, HARDWARE_ERROR, timeout…), sucesso sem mudança de estado, tempo até a mudança |
| Qualidade dos dados | *DNP3 · Qualidade*: chattering, eventos perdidos, pontos com qualidade ruim, relógio adiantado ou atrasado, NEED_TIME, estouro de buffer |
| Rede e telecom | *DNP3 · Rede, enlace e segurança*: RTT, retransmissões, CRC, link status, failover de FEP, master não autorizado |
| Debugar ao vivo | `http://VM:8080`: filtre por RTU ou texto, clique na linha para ver objetos, pontos e hex; aba RTUs com o estado em memória |
| Abrir no Wireshark | Botão "PCAP 15 min" no tail, link "Baixar PCAP do intervalo" no dashboard da RTU, ou `GET /api/pcap?rtu=ip:porta&from=<ms>&to=<ms>` |
| Reprocessar o histórico (novo indicador, correção) | `dnp3mon pcap /data/pcap/cap-*.pcap.gz -ch-url ...` (limpe antes o período no banco) |

**Inventário (opcional).** Ele permite agrupar por meio (LTE, rádio, satélite, fibra), região e nome:
```bash
docker compose exec -T clickhouse clickhouse-client --user dnp3mon --password "$CH_PASSWORD" \
  --query "INSERT INTO dnp3.rtu_inventory (rtu,name,substation,region,medium,vendor,model,notes) FORMAT CSVWithNames" < inventario.csv
```
O modelo está em `deploy/inventario_exemplo.csv`. Como a chave é `ip:porta`, dá para exportar do ADMS.

**Saúde do próprio monitor:**
- `GET /api/health` e `/metrics` (Prometheus): pacotes, descartes do kernel, fila, linhas gravadas, spool e PCAP.
- O alerta *Coleta DNP3 parada* dispara se nada for gravado por 3 minutos.
- O painel *Lacunas na captura* mostra perda no SPAN.

## Parâmetros principais (`.env` / flags)

| Variável | Padrão | Significado |
|---|---|---|
| `CAPTURE_IFACES` | — | interfaces de espelhamento, separadas por vírgula |
| `DNP3_PORTS` | 20000 | portas DNP3 |
| `AUTHORIZED_MASTERS` | vazio | IPs/CIDRs dos FEPs; DNP3 vindo de outro master gera alerta de segurança |
| `RESP_TIMEOUT` | 30s | tempo sem resposta para contar timeout (satélite e LTE pedem folga) |
| `OFFLINE_AFTER` | 10m | sem quadro válido por esse tempo = RTU offline (3 timeouts seguidos também derrubam) |
| `PCAP_DAYS` / `PCAP_MAX_GB` | 30 / 0 | retenção do PCAP por idade e por tamanho |
| `PCAP_EXTRA_PORTS` | 2404 | portas extras guardadas no PCAP (IEC 104 já fica guardado para a fase 2) |

Outros ajustes, por flag ou variável `DNP3MON_*`:
- `-feedback-window` (30s): janela para considerar a mudança de estado após um comando;
- `-static-mode` (`changes`): grava estáticos só quando mudam; `all` grava toda integridade;
- `-offline-timeouts` (3): quantos timeouts seguidos derrubam a RTU.

Retenção no banco (em `tools/gen_schema.py`):
- `messages` e `points`: 90 dias;
- `rtu_stats_1m`: 90 dias;
- `rtu_stats_1h`, `commands`: 2 anos;
- `events`: 1 ano.

## Desenvolvimento

```
cmd/dnp3mon      captura ao vivo / reprocessamento de pcap, API, sink
cmd/dnp3sim      simulador: N RTUs, FEPs, LTE/rádio/satélite/fibra, falhas injetadas
cmd/dnp3replay   injeta um pcap numa interface em tempo real
internal/dnp3    enlace (CRC), transporte, aplicação, objetos, pontos, comandos
internal/engine  fluxos TCP, sessões, correlação, comandos, pontos, estatísticas
internal/sink    ClickHouse (lotes + spool) e stdout
internal/pcapring PCAP rotativo, retenção e recorte
internal/web     API, SSE e página do tail ao vivo
tools/           geradores de schema, dashboards e alertas; validador das consultas; bundle
deploy/          docker-compose, ClickHouse, Grafana (plugin vendorizado)
```

```bash
go test ./...
go run ./cmd/dnp3sim -rtus 300 -dur 1h -o /tmp/s.pcap
go run ./cmd/dnp3mon pcap /tmp/s.pcap -no-db -http "" -stdout msg | head
python3 tools/gen_schema.py && python3 tools/gen_dashboards.py && python3 tools/gen_alerts.py
python3 tools/check_queries.py http://dnp3mon:SENHA@127.0.0.1:8123   # executa todas as consultas dos painéis
```

Validação feita: o simulador gera frames que o Wireshark (tshark) decodifica sem erro, exceto os CRC injetados de propósito. As contagens por function code do dnp3mon batem exatamente com as do tshark.

## Limitações conhecidas e próximos passos

- **IEC 104**: o tráfego já é guardado no PCAP, mas ainda não é decodificado (fase 2: APCI I/S/U, STARTDT/TESTFR, T1–T3, N(S)/N(R), COT, ACT/ACTCON/ACTTERM).
- **Retorno de estado do comando**: hoje considera a primeira mudança binária da mesma RTU. Com o mapa comando→ponto de status exportado do ADMS, a verificação fica exata.
- **Relatórios** diários e semanais em PDF/XLSX a partir do ClickHouse: ainda não implementados.
- DNP3 sobre UDP está implementado, mas não foi testado com tráfego real. DNP3 com TLS não é decodificável passivamente (não é o caso hoje).
- Validar com um PCAP real do ADMS antes de entrar em produção: objetos específicos de fabricante, variações pouco usadas e o comportamento dos FEPs redundantes.
