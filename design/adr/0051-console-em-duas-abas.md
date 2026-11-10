# 0051. O console colapsa em duas abas: "MCP Servers / APIs" e "Users"

**Status:** Accepted — 10 nov 2026. Fixa a arquitetura de informação do
console revisado; é o pré-requisito do trabalho de CRUD (M1/M2/M4). Supersede
e anota as partes de **navegação/IA** das ADRs `0036` e `0050`; não muda
nenhuma garantia de segurança delas. As ADRs `0052`–`0057` detalham cada
superfície citada aqui.

## Contexto

O console (`0036`, estendido por `0040` e `0050`) cresceu para oito páginas de
entidade — Overview, Tools, Secrets, Roles, Audit, Quota, Backends e People —,
cada uma uma aba própria. Para um time de ~7 pessoas que opera por túnel SSH,
isso espalha uma decisão (p.ex. "esta API está saudável, suas tools estão
aprovadas e seus segredos estão no cofre?") por quatro telas que não se
referenciam. Algumas abas também duplicam o que o SIEM já faz melhor (Audit) ou
expõem um controle que não se opera pela tela (Quota).

A API de gestão (`0040`) e seus portões não mudam: o front continua um cliente
fino de `pkg/adminapi` que só renderiza e confirma. O que muda é o mapa da
tela.

## Decisão

O console tem **duas abas**, e nada além delas no menu.

### Aba 1 — "MCP Servers / APIs"

A lista de backends pelo substantivo "MCP server / API" (`0052`), com a saúde
por backend (`0041`). Adicionar é uma sub-página dedicada `/servers/new`
(`0052`), não um modal. O **detalhe de um backend** absorve o que eram abas
soltas:

- suas **tools** (quarentena: pendentes, aprovar, revogar, clear) — era a aba
  Tools (`0056` não a toca; ela vem para cá, não para o SIEM);
- seus **segredos**, inline e com portão de root (`0053`), mais uma visão
  global pequena do cofre para segredos compartilhados/órfãos;
- o **toggle de manutenção** por backend (`0055`);
- **redial**.

### Aba 2 — "Users"

Uma aba com seções, cada uma com o seu portão de socket (`0040` §1):

- **People/accounts** — contas do IdP (`0038`), socket de contas (root);
- **Roles** — a visão estruturada papel×tool com concessão/revogação cirúrgica
  (`0054`), socket de contas;
- **Blocklist** — bloquear/desbloquear sujeito (`0031`), socket do operador.

Manter People e Blocklist distintos preserva `0038`: **desativar uma conta não
é bloquear um sujeito**, e as duas ações continuam existindo, separadas.

### O que sai do menu

- **Overview** — a identidade do operador vai para o cabeçalho; os itens que
  "precisam de revisão" aparecem na própria aba Servers.
- **Tools**, **Secrets** — para o detalhe do backend (acima).
- **Roles** — para a aba Users.
- **Audit** — para o SIEM (`0056`).
- **Quota** — para o CLI e o `gatte.status`; o controle continua ativo no
  servidor (`0057`).

### Restrições que não se cruzam (de `0036`/`0050`, reafirmadas)

- **Zero-JS** (`0036`): nada de modal em JavaScript; usa-se a sub-página
  `/servers/new` ou `<details>` de HTML.
- **Loopback + túnel SSH, link de uso único, sessão no caminho e no cookie,
  CSRF e `Origin`** (`0036` §3, `pkg/frontkit`): intocados — mudar a IA não
  reabre nenhuma dessas defesas.
- **Cada botão é a ação de mesmo nome da API** (`0040`): o front não ganha
  lógica de negócio ao reorganizar as telas.

## O que supersede e o que anota

- **`0036` §Decisão 1 e §2 (a enumeração de abas/botões):** a lista de páginas
  e a navegação do console passam a ser as duas abas acima. As defesas do §3 e
  os testes do §Testes continuam valendo integralmente.
- **`0050`:** registrar/assinar/remover API, segredos e papéis continuam
  existindo exatamente como lá decidido; o que muda é **onde** aparecem na tela
  (detalhe do backend e aba Users), não o seu comportamento nem os seus
  portões.

## Consequências

- Uma decisão operacional por backend cabe numa página só; a lista e o detalhe
  substituem quatro abas de ida e volta.
- As `~6` fatias de M1 se repartem por superfície (lista/add/detalhe; tools;
  secrets; people/blocklist; roles; limpeza de nav) e colidem menos, porque a
  IA está fixada aqui antes de qualquer página ser escrita.
- Nenhuma mudança de contrato nem de segurança decorre desta ADR: ela é mapa de
  tela. As remoções de superfície de servidor (manutenção, quota, audit) têm
  ADR própria (`0055`, `0057`, `0056`).
