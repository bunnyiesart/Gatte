# 0002. Go como linguagem de implementação do gateway

**Status:** Accepted — decidido por bunnyiesart em 08 set 2026, revertendo a
proposta original deste ADR (Python). Ver "Decisão" abaixo.

## Contexto

Com o estilo monolítico modular decidido (`0001`), é preciso escolher a
linguagem/runtime de implementação. Isso é decisão arquiteturalmente
significativa (`04-adrs.md` §2, critério "Técnicas de construção") porque
afeta quem consegue manter o sistema depois de construído — não é escolha
neutra de gosto.

## Alternativas

### Opção A — Python

| Prós | Contras |
|---|---|
| Todos os quatro servidores MCP atuais (`casemgmt`, `logsearch`, `docsearch`, `threatintel`) já rodam Python dentro de seus containers Docker — **manutenibilidade** | Menos comum que Go para binários-únicos-fáceis-de-distribuir (mas containerizar remove boa parte dessa desvantagem) |
| `fortigate_report.py`, `patrus_report.py`, `kerberos_report.py` — os três scripts candidatos a virar tools (**extensibilidade**) já são Python; zero fricção de linguagem para incorporá-los | Assinatura Ed25519 e hashing SHA-256 (padrões que vamos copiar do Wirken/mcpproxy-go) são mais idiomáticos em Go nos projetos de referência, mas ambos têm bibliotecas Python maduras (`cryptography`, `hashlib`) |
| `sops` tem binding Python confirmado (§9.3 do `DEVELOPMENT-LOG.md`) | — |
| A equipe (SOC, não plataforma) já escreve e mantém Python — **simplicidade & deployability**: nenhuma linguagem nova para o único operador aprender | — |

### Opção B — Go

| Prós | Contras |
|---|---|
| Os dois candidatos mais próximos do que testamos (ToolHive, mcpproxy-go) são Go — mecanismos de referência (`Provider`, hash de quarentena) mapeiam 1:1 | **Nenhum** dos quatro servidores atuais é Go — introduziria uma segunda linguagem no stack para a mesma equipe pequena manter |
| Binário único estaticamente linkado, deploy trivial | Curva de aprendizado para quem só escreve Python hoje — vai contra "simplicidade & deployability" no eixo que importa aqui: manutenção pela equipe, não deploy |

## Decisão

**Vamos usar Go.** Decisão explícita de bunnyiesart em 08 set 2026, contra a
proposta original deste ADR (Python) — registrada aqui em vez de um novo
ADR porque este é exatamente o documento que existia para receber essa
confirmação (`WORKFLOW.md` Gate 0, item 2).

**Justificativa técnica:** os dois candidatos com o design mais próximo do
que este projeto reimplementa — ToolHive (`Provider` de segredos) e
mcpproxy-go (quarentena por hash) — são Go; os mecanismos descritos em
`DEVELOPMENT-LOG.md` §9.2 mapeiam 1:1 para o código-fonte deles nessa
linguagem. Binário único estaticamente linkado simplifica o deploy do
`Gateway Endpoint` como processo único (`design/adr/0001`).

**Justificativa de negócio:** nenhum dos quatro servidores atuais
(`casemgmt`, `logsearch`, `docsearch`, `threatintel`) nem os três scripts candidatos a
tool (`fortigate_report.py`, `patrus_report.py`, `kerberos_report.py`) são
Go — isso introduz uma segunda linguagem no stack que a equipe de SOC
mantém. Essa é exatamente a troca que a Opção A deste ADR (abaixo) já
sinalizava como custo; foi pesada e aceita conscientemente, não ignorada.

## Consequências

**Impactos positivos:** alinhamento direto com os dois candidatos de
referência mais próximos (ToolHive, mcpproxy-go) — os mecanismos
reimplementados (`Provider` de segredos, hash de quarentena SHA-256,
assinatura Ed25519) podem ser conferidos linha a linha contra o
código-fonte já lido, em vez de traduzidos de conceito; binário único sem
runtime interpretado facilita o deploy do processo único do `Gateway
Endpoint`.

**Impactos negativos aceitos:** os três scripts de relatório
(`fortigate_report.py`, `patrus_report.py`, `kerberos_report.py`) e os
quatro servidores MCP atuais continuam em Python — não há reuso direto de
código entre eles e o gateway; qualquer integração futura passa por
processo separado (stdio/HTTP), não por biblioteca compartilhada. A equipe
que mantém isso hoje não escreve Go rotineiramente — custo de aprendizado
aceito explicitamente por bunnyiesart, não avaliado como zero.

**Trade-offs assumidos:** trocamos "zero linguagem nova para a equipe"
(o que a Opção A deste ADR levantava a favor de Python) por "alinhamento
com os mecanismos de referência e um binário de deploy mais simples" — a
decisão de negócio final é de bunnyiesart, registrada aqui para não
re-litigar sem um novo ADR (`AGENTS.md` §2).

## Compliance

- [ ] Automatizável? N/A — decisão única de setup de projeto, não regra
  contínua.
- Mecanismo: nenhum — a confirmação em si era o gate, e foi satisfeita.

## Notas

- Autor: investigação conjunta (bunnyiesart + Claude); decisão final de
  bunnyiesart, 08 set 2026.
- Ver `WORKFLOW.md` Gate 0 — este ADR sendo `Accepted` é uma das duas
  condições para começar a Fase 1.
