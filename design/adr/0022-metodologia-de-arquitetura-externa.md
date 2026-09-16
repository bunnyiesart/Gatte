# 0022. A metodologia de arquitetura é externa a este repositório, e como citá-la

**Status:** Accepted — 15 set 2026.

## Contexto

Quinze arquivos deste repositório citam `docs/context/` — nove deles em
comentários de doc do Go, e um como **pré-condição escrita**: o `AGENTS.md`
§5 manda ler `docs/context/05-testabilidade-e-contratos.md` *antes da
primeira classe ser escrita*.

**`docs/context/` nunca existiu.** Não em nenhum dos 51 commits, não como
arquivo removido, não em `git ls-files` de nenhuma revisão. A pré-condição
ficou escrita durante as sete fases inteiras, inexequível de dentro de um
clone, e ninguém tropeçou nela — que é o que acontece com instrução que
aponta para o vazio: ela não falha, ela é pulada.

O material existe e está íntegro. Fica em `soc-n1-v2/context-new/`, **irmão
deste repositório e não descendente dele**: sete arquivos com exatamente os
nomes citados, de `01-descoberta-e-pensamento-arquitetural.md` a
`07-fitness-functions.md`. Ninguém achava porque o diretório mudou de nome
em algum momento e as citações não.

Então não há nada a recuperar, e há uma decisão a tomar: o que este
repositório afirma sobre um corpus que ele não contém.

## Alternativas

### Opção A — Trazer os sete arquivos para `docs/context/`

| Prós | Contras |
|---|---|
| Toda citação passa a resolver; a pré-condição do §5 vira executável | **É uma decisão de redistribuição, não de organização.** Este repositório é público e não tem `LICENSE`; o corpus é destilação de quatro livros protegidos que ele cita nominalmente |
| O leitor do clone tem tudo à mão | O `AGENTS.md` §2 já gasta um parágrafo recusando vendorizar código MPL-2.0 da MCPJungle, que teria direito de *ler*. Vendorizar prosa derivada de livro seria aplicar um padrão mais frouxo ao material com a origem mais delicada |

### Opção B — Apagar as citações

| Prós | Contras |
|---|---|
| Nenhuma afirmação falsa sobra | Apaga a genealogia: a forma de oito componentes, o formato de ADR, a regra de ports & adapters e as fitness functions vêm de algum lugar, e um leitor que não sabe de onde não consegue julgar se foram bem aplicadas |
| Barato | Troca uma afirmação errada por uma omissão, que é o defeito mais difícil de detectar depois |

### Opção C — Declarar externa e nomear onde vive (escolhida)

| Prós | Contras |
|---|---|
| A genealogia fica, e a grafia deixa de afirmar que o arquivo está aqui: `context/04-adrs.md`, com o §6 do `AGENTS.md` dizendo o que é `context/` e onde ele está | Quem clona este repositório sozinho **não consegue abrir** os sete arquivos. É uma perda real e fica escrita em vez de escondida |
| Nenhuma decisão de redistribuição é tomada por inércia | Depende de o caminho externo continuar existindo na máquina de quem lê |

## Decisão

**Opção C.** A metodologia é externa, as citações passam a dizer isso, e o
`AGENTS.md` §6 é o único lugar que diz onde o corpus vive.

### 1. A grafia muda, o conteúdo da citação não

`docs/context/NN-*.md` vira `context/NN-*.md` em todas as ocorrências —
markdown e comentários de doc do Go. É deliberadamente uma mudança pequena:
o valor da citação está em dizer *de onde a regra veio*, e isso continua
inteiro. O que sai é a afirmação implícita de que o arquivo está neste
repositório.

### 2. A pré-condição do §5 é reescrita para o que ela pode exigir

Mandar ler um arquivo que o leitor não tem não é pré-condição, é ruído. Ela
passa a nomear o corpus externo e a dizer o que fazer quando ele não estiver
à mão — seguir ports & adapters e injeção por construtor, que é o que
aqueles arquivos ensinam e o que o código inteiro já demonstra.

### 3. Não vendorizamos, e a reabertura fica condicional e escrita

Se o dono tiver direito de redistribuição sobre o corpus — ou produzir uma
versão própria que não dependa do material protegido —, a Opção A volta à
mesa e este ADR ganha um bloco de correção. Enquanto isso não for
verificado, a ausência de `LICENSE` neste repositório público é razão
suficiente para não trazer 195 KB de prosa derivada para dentro dele.

A ausência de `LICENSE` é um problema separado e fica nomeada aqui como
fora de escopo, para não ser descoberta de novo pelo próximo que perguntar.

### 4. O que impede a reincidência é um manifesto, não um scanner

A tentação óbvia era uma fitness function que varresse todo caminho entre
crases e exigisse que resolvesse. Quatro protótipos independentes deram
quatro respostas diferentes — de 269 a 676 ocorrências, com 52 a 223
"faltantes" — porque `127.0.0.1`, `audit.Record`, `pkg/secrets/types.go` e
`dfir.bunnyiesart.com` também são tokens entre crases. Distinguir afirmação
sobre este repositório de identificador exige conhecimento de domínio, que é
precisamente o que `context/07-fitness-functions.md` §2 diz que uma fitness
function não pode exigir para rodar. A regra larga também seria empiricamente
falsa: a maioria dos caminhos entre crases aqui **não** afirma existência.

O que entra é um **manifesto de asserções**: uma lista explícita, escrita à
mão, dos caminhos que os documentos-portão deste repositório mandam abrir —
`AGENTS.md` §5 e §6, `WORKFLOW.md`, os cabeçalhos de `design/01-03` e os
nove comentários de doc do Go. Cada um é verificado como existente. Zero
allowlist, zero falso positivo, e teria pego `docs/context` no commit de
bootstrap pelo mesmo mecanismo pelo qual pega o próximo.

**O manifesto não varre o corpus externo.** Ele afirma o que está *aqui*;
`context/` é, por esta decisão, deliberadamente não verificável de dentro.

## Consequências

**Impactos positivos:** as 22 ocorrências passam a dizer a verdade; a
genealogia da arquitetura continua legível; e a reincidência tem um portão
que roda em `make check` em vez de depender de alguém reparar.

**Impactos negativos aceitos:**

- **Quem clona este repositório não abre os sete arquivos.** Isso é uma
  perda para um leitor externo, e a Opção A a resolveria. Aceita pelo motivo
  do item 3, e não por custo.
- **Uma citação para fora pode envelhecer sem aviso.** Se `context-new/` for
  renomeado de novo, nada aqui detecta — pelo item 4, o manifesto não olha
  para lá de propósito. O §6 do `AGENTS.md` é o único ponto a atualizar.

**Trade-offs assumidos:** trocamos a conveniência do leitor pela recusa de
tomar, por inércia, uma decisão de redistribuição sobre material de
terceiros num repositório público sem licença.

## Compliance

- [x] Automatizável? Sim — o manifesto do item 4.
- Onde vive: `internal/fitness/manifest_test.go`,
  `TestDocumentedPathsExist`. A lista é dado no próprio teste, e acrescentar
  um caminho a um documento-portão sem acrescentá-lo ali é a única forma de
  burlar — deliberadamente, porque o alvo é a citação que um documento-portão
  manda seguir, não toda string que pareça um caminho.
- Quando roda: a cada build/CI.

## Notas

- Autor: bunnyiesart + Claude, 15 set 2026, a partir de um achado de um
  workflow de revisão: `docs/context/` referenciado em 15 arquivos e
  inexistente em 51 commits.
- bunnyiesart confirmou, na mesma conversa, não ter direito de
  redistribuição sobre o corpus — é o que fecha a Opção A por ora.
