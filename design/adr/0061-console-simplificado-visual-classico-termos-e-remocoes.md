# 0061. Console e TUI simplificados: visual clássico, termos simples, sem auditoria nem blocklist na tela

**Status:** Accepted — 10 nov 2026. Vale para os dois fronts: o console web
(`internal/front/gatteweb`) e o TUI (`internal/front/gattetui`). Supersede a
cópia de `0060` §1/§2 (os termos "attest"), a seção Blocklist da aba Users de
`0051` e a lista "quem a trilha viu" de `0038` §1 e `0046`. Anota `0051`,
`0054` e `0056`. Não muda a API de gestão, o CLI, a assinatura, a quarentena
nem a trilha de auditoria.

## Contexto

Depois de `0051`–`0060`, o console tem duas abas, mas ainda carrega coisas que
pesam mais do que ajudam a um time de ~7 pessoas:

- **Palavras difíceis.** "Attest", "Redial", "Deregister" e "Tool safety" são
  termos de quem escreveu o gateway, não de quem o opera. `0060` já trocou
  "Signed" por "Config attested" para não confundir assinatura com segurança;
  "attest" continua sendo uma palavra que o operador precisa traduzir.
- **Visões de auditoria espalhadas.** `0056` tirou a página Audit, mas ficaram
  pedaços de leitura da trilha: "Seen on the gateway" (aba Users e página da
  conta) e o marcador de pendência "Waiting on you" na lista de servidores. Ler
  auditoria é trabalho do SIEM — o Wazuh é o SIEM principal; o caminho do
  Graylog fica durante a migração.
- **Blocklist na tela.** Bloquear um sujeito é a rede de segurança de
  incidente (`0031`): corta um token já emitido, o que desativar a conta não
  faz (`0038`). É uma ação rara, de resposta a incidente, que já tem CLI; na
  tela ela compete com as ações do dia a dia.
- **Ações de tool em linha.** Aprovar, revogar, clear e revisar aparecem como
  botões soltos em cada linha da tabela de tools, o que deixa o painel denso.
- **Visual.** O dono quer um visual mínimo e direto, igual nos dois fronts.

## Decisão

### 1. Visual: "classic system UI"

Os dois fronts seguem a aparência de interface de sistema dos anos 90: painéis
cinza, bordas chanfradas de 1px, fonte de sistema simples, botões quadrados.
Mínimo, retrô, CSS simples, sem framework.

- **Console:** só CSS em `ui/app.css`. **Zero-JS continua** (`0036`).
- **TUI:** o mesmo espírito no terminal — painéis cinza, bordas de linha,
  botões quadrados no estilo `[ OK ]`.
- Sem emoji; o estado vem da cor e do texto (regra de saída de UI).

### 2. Termos mais simples (só cópia de UI)

| Antes | Depois |
|---|---|
| `Attest this configuration` | `Approve configuration` |
| `Config attested` | `Config approved` |
| `Config not attested` | `Config not approved` |
| `Attestation invalid` (a assinatura não confere mais com a config) | `Changed since approved` |
| `Redial` | `Reconnect` |
| `Deregister` | `Remove` |
| `Tool safety` | `Tool security` |

- **O significado de `0060` não muda:** aprovar a configuração é a assinatura
  de um operador sobre a config (URL ou comando, args, nomes dos segredos), não
  uma afirmação de que o servidor ou as tools são seguros. A legenda do selo e
  do botão diz isso com as palavras novas.
- **As tools mantêm "Approve tool".** Os dois portões continuam com nomes
  distintos: "Approve configuration" no servidor, "Approve tool" na tool.
- **Só cópia.** Os campos da API, os comandos do CLI (`sign`, `upstream
  redial`, `upstream deregister`) e a assinatura ficam como estão.

### 3. Nenhuma visão de auditoria na UI

Nem o console nem o TUI mostram dados da trilha:

- sai **"Seen on the gateway"** — da aba Users e da página da conta;
- sai o marcador de pendência **"Waiting on you"** da lista de servidores.

O gateway **continua gravando toda chamada**: a trilha SQLite encadeada por
hash e o sink JSONL enviado ao Wazuh (`0017`, `0056`) não mudam. Toda leitura
de auditoria acontece no Wazuh, o SIEM principal (o caminho do Graylog fica
durante a migração). As tools pendentes continuam visíveis no painel de tools
de cada servidor: isso é estado da quarentena, não auditoria.

O offboard (`0046`) deixa de oferecer a lista "quem a trilha viu" como
seletor: o operador digita o subject (o campo digitado já existe). Continua
valendo que nada vem pré-selecionado.

> **Anotação (10 nov 2026, M6.1).** Sai o marcador de pendência das tools
> que esperam revisão, mas uma tool cuja definição **mudou depois de
> aprovada** continua sinalizada na lista de servidores ("Tool changed", em
> vermelho, por backend): é o sinal de troca de definição (rug pull) e não
> pode ficar escondido dentro da página do servidor. É estado da quarentena,
> não auditoria.

### 4. Blocklist sai da UI; fica no CLI

A seção Blocklist sai da aba Users do console e da tela Users do TUI. A
capacidade fica inteira no CLI — `mcp-gateway access block|unblock|list` —
como rede de segurança de incidente: **desativar uma conta não corta um token
já emitido; bloquear corta** (`0031`, `0038`). A API de bloqueio
(`/v1/access/*`) e o bloqueio feito pelo offboard (`0046`) não mudam.

A aba Users passa a ter duas seções: **People** e **Roles**.

### 5. Ações de tool num menu por tool

Aprovar, revogar, clear e revisar uma tool passam para um menu que abre ao
clicar, um por tool, feito com `<details>`/`<summary>` — sem JS (`0036`). Cada
item do menu continua sendo a ação de mesmo nome da API, com CSRF e
confirmação como hoje (`0040`). No TUI, as mesmas ações ficam agrupadas num
menu por tool.

> **Anotação (11 nov 2026, M6.1).** Os itens do menu que se ligam ao que o
> operador viu — aprovar (a definição e o fingerprint) e clear (os papéis
> `non_read` que passam a alcançar a tool) — abrem a página de revisão da
> tool, onde a ação acontece. Só o revogar é enviado direto do menu.

### Restrições que não se cruzam

- Loopback + túnel SSH, link de uso único, sessão, CSRF e `Origin` (`0036` §3,
  `pkg/frontkit`): intocados.
- Cada botão continua sendo a ação de mesmo nome da API (`0040`); o front não
  ganha lógica.
- `pkg/adminapi` continua completo: os métodos de auditoria e de bloqueio
  ficam no cliente; os fronts só deixam de chamá-los.

## O que supersede e o que anota

- **`0060` §1/§2:** a cópia "Config attested / Config not attested / Attest
  this configuration" (e "Attestation invalid") e o cabeçalho "Tool safety"
  passam a ser os da tabela do
  §2 acima. O §3/§4 de `0060` (sem emoji; nada muda sob a cópia) continuam.
- **`0051`:** a aba Users perde a seção Blocklist (fica People + Roles); "os
  itens que precisam de revisão aparecem na aba Servers" deixa de valer como
  marcador na lista; "redial" passa a se chamar "Reconnect" na tela.
- **`0038` §1 e `0046`:** a lista "quem a trilha viu" sai da tela.
- **`0054`:** sem mudança na seção Roles; só passa a ser uma de duas seções.
- **`0056`:** estendida — além da página Audit, nenhuma outra visão da trilha
  fica na UI; o SIEM principal é o Wazuh.

## Consequências

- O operador lê palavras do dia a dia, e os dois portões (configuração e tool)
  seguem com nomes distintos.
- A UI faz menos: sem leitura de trilha, sem blocklist. A trilha é lida num
  lugar só (o Wazuh), e o bloqueio fica onde a resposta a incidente já opera
  (o CLI).
- Quem precisa bloquear durante um incidente usa o CLI; não há botão de
  bloqueio na tela. Essa é a troca aceita.
- O painel de tools fica mais limpo: uma linha por tool, as ações num menu.
- A mudança é de CSS, template e texto nos dois fronts, mais a remoção de
  seções. Nenhum contrato muda. M6.1 aplica isto ao console e M6.2 ao TUI.

## Não cobre

- Qualquer mudança na API de gestão, no CLI, na assinatura, na quarentena ou na
  trilha de auditoria.
- A paleta e as medidas exatas do visual: ficam com M6.1/M6.2, dentro do §1.
