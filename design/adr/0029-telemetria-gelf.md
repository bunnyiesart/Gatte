# 0029. Telemetria GELF: uma cópia do trail que nunca segura o request

**Status:** Accepted — 28 set 2026.

## Contexto

O `0017` já tira o trail do host: uma linha JSONL por registro, com o elo da
cadeia, para um shipper encaminhar ao SIEM. Isso pede um shipper rodando ao
lado do gateway. Num host que se quer leve, o shipper é mais um processo para
instalar, configurar e vigiar. E um Graylog costuma já ter um input GELF
esperando mensagens.

A linha interna de onde este repositório foi higienizado construiu esse
caminho depois da separação, no seu `0022`, que nunca foi publicado aqui.
Este ADR o traz na convergência das duas linhas decidida em 28 set 2026, com
uma mudança de fiação (item 1).

## Decisão

Um sink **adicional** e **opcional**: cada registro que o Audit Trail
**aceitou** vira uma mensagem GELF, enviada por UDP ou TCP (com TLS opcional
no TCP) a um input do Graylog. A seção `[telemetry]` ausente é o estado
normal, e nesse estado nada sai do processo.

### 1. Um ponto de acoplamento, e é o composition root

`telemetryRecorder` (`cmd/mcp-gateway/telemetry.go`) decora o gravador de
auditoria mais externo, depois do SQLite e depois do sink JSONL. `Record`
grava na fonte de verdade primeiro e só copia o que ela aceitou. Um registro
recusado não é emitido: seria o SIEM afirmando uma chamada que a evidência
não tem.

**Diverge da linha interna.** Lá o sink era um campo de `gateway.Config`,
chamado de dentro do `Dispatch`. Aqui o pacote `gateway` não sabe que a
telemetria existe, e o domínio continua com uma porta de auditoria só.

### 2. A porta recebe `audit.Record`, não um tipo próprio

Com um tipo próprio, alguém acrescenta `args` ou latência à mensagem sem
tocar no trail, e o gateway passa a emitir para fora do processo um dado que
a fonte de verdade não tem. No caso de `args`, esse dado é controlado pelo
cliente e pode conter uma credencial colada por um analista. Com
`audit.Record` na assinatura, alargar o que sai exige mudar o trail primeiro.

### 3. Não-bloqueio é propriedade da assinatura

`Emit` não recebe `ctx` e não devolve erro. Nenhuma condição (destino fora do
ar, DNS falhando, socket cheio, fila cheia) atrasa ou altera o request.

### 4. Fila limitada, e o descartado é o mais novo

`buffer` (padrão 4096, mínimo 64). O que não cabe é descartado e contado.
Não há spool em disco: a recuperação de uma lacuna é o próprio trail,
`mcp-gateway audit --since …`.

### 5. Erro local derruba o arranque; indisponibilidade remota nunca

Um endereço que não é `host:port`, um transporte que não é `udp`/`tcp` ou um
arquivo de CA ilegível recusam a carga. Um destino inalcançável não recusa
nada: o SIEM fora do ar nunca pode ser este processo fora do ar.

### 6. O operador descobre por três canais, nenhum por evento

- a linha `mcp-gateway: telemetry` no arranque, com o destino ou `none`;
- a transição para "não saudável" e a volta, cada uma logada uma vez;
- a mensagem `_event_kind=telemetry_gap` enviada na recuperação.

### 7. Contabilidade que fecha

`Emitted == Written + DroppedFull + DroppedWrite + DroppedOversize +
DroppedClosing + Queued`, a qualquer momento (`telemetry.Stats`).

## O que nunca entra em mensagem nenhuma

Valor de credencial, o token apresentado numa falha de autenticação (nem
truncado), o texto de erro do upstream, os `args` da chamada e o conteúdo do
resultado. Vão os sete campos do registro, com os nomes do `mcp-gateway audit
-json`, mais `host` e `_cliente_soc`.

*Correção, 30 set 2026:* desde a ADR-0037 o registro tem **oito** campos:
o oitavo, o nome de exibição, vai como `_analyst_name`, só quando diz algo
que `_analyst_identity` não diz (`internal/telemetry/gelf/message.go`). O
que nunca entra, acima, não muda.

## Consequências

- Um host sem shipper pode mandar o trail direto ao Graylog.
- **Uma chamada que falha produz duas mensagens** (`allowed` em T, `failed`
  em T+n, `0012`). Conte `_outcome:allowed` para tentativas.
- UDP não confirma nada além de o datagrama ter saído do socket. TCP percebe
  destino morto, mas ainda não confirma indexação.
- A cópia GELF não carrega o elo da cadeia. A comparação de cabeça (`0017`)
  continua sendo trabalho do sink JSONL.

## Compliance

- `internal/telemetry/gelf`: testes do adaptador, incluindo o de vazamento.
- `internal/config`: `TestNoTelemetrySectionIsNotConfiguredAndNotAnError`,
  `TestExampleConfigDocumentsTheTelemetry` e uma regra de validação por
  teste.
- `cmd/mcp-gateway`: `TestTelemetryRecorder_CopiesOnlyWhatTheTrailAccepted`
  e `TestTelemetryRecorder_ShipsGELFOverUDP`.
