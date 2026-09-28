# 0032. Quarentena informada: definições guardadas, aprovação com o que foi visto, eventos na trilha

**Status:** Accepted — 28 set 2026.

## Contexto

A aprovação da quarentena (`0007`) é o único ponto humano contra tool
poisoning e rug pull, e até aqui era um carimbo num hash. A tabela
`quarantined_tools` guardava só fingerprints; `tool approve` aprovava
"o que estiver sendo anunciado agora" e, para uma ferramenta `changed`,
dizia que não podia mostrar diff porque a definição aprovada nunca tinha
sido guardada. O operador lia a definição fora de banda e não conseguia
ligar o que leu ao hash que aprovou.

Além disso, `endpoint.go` descartava o retorno de `Observe`: uma ferramenta
nova e a reescrita de uma aprovada — os dois eventos que este componente
existe para pegar — não geravam log, linha na trilha nem nada que o SIEM
pudesse alertar. Uma assinatura recusada ia só para o slog. E o nome da
ferramenta, escolha do backend, não era validado: chegava ao modelo, ao
terminal do operador e à trilha com o que viesse, incluindo ESC, bidi e
caracteres de tag.

## Decisão

1. **Toda definição observada é guardada**, em `tool_definitions(hash PK,
   name, description, input_schema, output_schema, first_seen_at)`, na mesma
   transação de `Observe`. A chave é `quarantine.Hash` da própria linha;
   `INSERT OR IGNORE`, e triggers recusam `UPDATE` e `DELETE`. `Forget` não
   apaga. `Store.Definition` refaz o hash na leitura e recusa com
   `ErrDefinitionMismatch` uma linha editada por fora — os triggers não
   impedem quem tem o arquivo, a checagem pega. Cresce por definição
   distinta, não por observação.

2. **`tool show SERVER TOOL`** imprime o estado, a definição observada e,
   quando difere, a aprovada e um diff de linhas (LCS) entre as duas. Uma
   aprovação anterior a esta ADR não tem definição: o console diz "was not
   kept" em vez de imprimir um bloco vazio.

   **`tool approve` exige `-fingerprint`.** Imprime antes o que está sendo
   aprovado (a definição, ou aprovada + observada + diff para `changed`).
   Sem `-fingerprint` não aprova nada e mostra o fingerprint atual e o
   comando a rodar; com um fingerprint diferente do observado, recusa. Se a
   definição observada não está guardada (linha de binário anterior), recusa
   até a próxima descoberta guardá-la. Para `changed`, falha de escrita da
   saída continua impedindo a aprovação.

3. **Escape visível** (`internal/visible`): todo code point não gráfico
   (C0, C1, DEL, formato — zero-width, bidi `U+202A-202E`/`U+2066-2069`,
   BOM, tags `U+E0000-E007F`), privado, separador, espaço que não seja
   `U+0020`, seletor de variação e demais default-ignorable sai como
   `\u{XXXX}`; byte UTF-8 inválido sai como `\x{XX}`. Escapa, não apaga: o
   caractere é evidência. A descrição mantém suas quebras de linha como
   estrutura. A barra invertida não é escapada, então um `\u{202E}` literal
   lê igual a um escapado; os dois são visíveis, e `-json` tem os bytes
   crus. O mesmo escape vale para `tool list` e `audit` (nome de probe,
   sujeito, motivo, origem).

4. **Eventos na trilha, só na transição.** Três linhas que o gateway
   escreve sobre si mesmo:

   | evento | `tool` | `reason` |
   |---|---|---|
   | primeira observação | `servidor.ferramenta` | `tool first seen: sha256:OBS` |
   | aprovada → changed | `servidor.ferramenta` | `tool changed: sha256:APR -> sha256:OBS` |
   | assinatura recusada | `(registry entry)` | `signature refused: invalid` ou `: unsigned` |

   Caller `(gateway)`, outcome **`denied`**, sem origem. Não é um quarto
   outcome: cada um é o gateway recusando servir algo (ferramenta pendente,
   ferramenta mudada, upstream), que é o que `denied` significa, e
   `audit.Outcome` segue o conjunto fechado de três contra o qual buscas
   salvas, `audit -outcome` e os contadores do heartbeat foram escritos. O
   que separa estas linhas das recusas de chamada é o caller e o prefixo do
   motivo; uma busca no SIEM casa `caller:"(gateway)"` e o prefixo. O
   motivo só carrega texto do gateway (hashes, `invalid`/`unsigned`).

   A transição da quarentena é decidida na transação que a grava
   (`quarantine.EventOf`), então um refresh que re-observa a cada intervalo
   gera uma linha, não uma por tick; `changed` que muda de novo não gera
   outra. A recusa de assinatura é lembrada em memória por upstream (sob
   `refreshMu`): uma linha quando começa, outra só depois de uma aceitação
   no meio, e um restart anuncia de novo o que encontrou. Store de
   assinaturas ilegível não é recusa e não gera linha. Sem rate limit:
   `changed` é pegajoso e não oscila.

5. **Heartbeat com `pending` e `changed`**, lidos do store (todo upstream
   que a quarentena conhece, como `tool list`), `-1` quando a leitura falha
   — nunca `0`, que é o "tudo limpo". `jsonl.Version` vai a `3`.

6. **Nome de ferramenta fora de `^[A-Za-z0-9_-]{1,64}$` é recusado na
   descoberta**, antes da quarentena: sem linha, sem evento, sem rota; o
   erro nomeia o upstream e mostra o nome escapado e truncado. O ponto fica
   fora de propósito: é o `NameSeparator`, e `b.c` em `a` lê igual a `c` em
   `a.b`.

## Consequências

- Mudança incompatível do console: scripts que chamavam `tool approve
  SERVER TOOL` passam a sair com 1 sem aprovar. O caminho é ler
  `observed_hash` de `tool list -json` (ou do próprio erro) e passar
  `-fingerprint` — `deploy/vm/gateway-serve-verify.sh` faz isso.
- Uma ferramenta com ponto no nome, antes servida como `up.a.b`, deixa de
  ser servida (`TestConnect_ADottedToolNameIsRefused`).
- O contador `denied` do heartbeat e de `Status` inclui estas linhas;
  quem conta recusas de analista filtra o caller `(gateway)`.
- Depois do upgrade, baselines existentes não têm definição: o primeiro
  `changed` delas mostra só o observado. As definições observadas são
  guardadas na primeira descoberta.
- Fora do escopo: quem aprovou continua fora da trilha (a CLI não escreve
  na cadeia); resultados de ferramenta não são escapados; nada julga o
  texto pelo operador.

Testes: `TestObserve_KeepsTheDefinitionItFingerprinted`,
`TestDefinitions_AreAppendOnly`, `TestObserve_ReportsOnlyTheTransition`,
`TestEscape_ShowsEveryInvisibleCodePoint`,
`TestRunToolShow_DiffsApprovedAgainstObserved`,
`TestRunToolApprove_WithoutFingerprintRefusesAndSaysWhatToRun`,
`TestRefresh_AuditsFirstSightAndRugPullOnceEach`,
`TestReconcile_AuditsASignatureRefusalWhenItStarts`,
`TestConnect_RefusesAToolNameOutsideTheCharset`,
`TestServeStack_HeartbeatCarriesTheQuarantineBacklog`.
