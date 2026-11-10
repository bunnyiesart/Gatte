# 0060. Os rótulos "Signed/Unsigned" dizem "Config atestada pelo operador", separada da segurança da tool

**Status:** Accepted — 10 nov 2026. Anota a cópia de interface de `0036`,
`0050` e `0052`. Não muda o que a assinatura é nem faz (`0003`, `0006`,
`0010`): muda só as palavras que a tela usa para ela, para que o operador não
leia "assinado" como "seguro".

## Contexto

A tela marca cada backend como **"Signed"** ou **"Unsigned"**. Um operador com
pressa lê "Signed" como "este servidor é seguro". **Não é isso que a palavra
diz.** No Gatte, "assinado" significa uma coisa precisa e estreita:

- um operador **atestou criptograficamente a configuração da entrada** — a URL
  ou o comando, os args e os **nomes** das variáveis de ambiente — com a chave
  Ed25519 (`internal/signer.Canonical`, `0003` item 3, `0006`). É a condição
  para servir (`0010`).

A assinatura diz que a config é a que um operador revisou e avalizou. **Não diz
nada** sobre o servidor ou as tools serem seguros. A segurança da tool é um
portão **separado**: a aprovação por fingerprint na quarentena (`0007`/`0032`)
e, para uma tool sensível, o `clear` mais um papel `non_read` que a nomeie
(`0048` §5). Dois operadores podem assinar uma config perfeitamente atestada de
um backend cujas tools ninguém deveria aprovar.

Misturar as duas coisas numa palavra ("Signed") treina o operador a baixar a
guarda no portão que importa. O dono pediu (10 nov 2026) que a tela diga a
atestação por extenso e a mantenha visivelmente separada da segurança da tool.

## Decisão

### 1. Renomear os rótulos de estado do backend

| Antes | Depois |
|---|---|
| `Signed` | `Config attested` |
| `Unsigned` | `Config not attested` |

O botão que hoje diz "Sign" na página de resultado do registro (`0050` §5,
`0052` §3, `0059` §6) passa a dizer **"Attest this configuration"**.

### 2. A cópia exata (inglês, sem emoji — regra de saída de UI)

**Selo de backend atestado** — rótulo `Config attested`, com a legenda:

> An operator signed this server's configuration — its URL or command, its
> arguments, and the names of its secrets — with the gateway key. This attests
> the configuration was reviewed. It is not a statement that the server or its
> tools are safe: tool safety is the separate approve and clear step below.

**Selo de backend não atestado** — rótulo `Config not attested`, com a legenda:

> No operator has signed this server's configuration. It is not served until a
> configuration is attested.

**Botão na página de resultado do registro** — `Attest this configuration`,
com a sub-legenda:

> Sign the configuration shown above with the gateway key. Review the URL or
> command, the arguments, and the secret names first — this signature attests
> exactly what is shown, nothing about the tools.

**Cabeçalho do painel de tools** (no detalhe do backend, `0051`), para separar
visivelmente os dois portões — `Tool safety` (ou `Tool safety — quarantine`),
mantendo as ações com os nomes que já têm (`Approve`, `Revoke`, `Clear`), e,
quando útil, a linha:

> Attesting the configuration does not approve any tool. Each tool is reviewed
> and approved here, by its fingerprint; a sensitive tool also needs Clear.

### 3. Sem emoji; o estado vem da cor e do texto

Os selos usam cor e texto, nunca emoji (regra de saída de UI do projeto). O
estado "not attested" é tratado como um aviso de bloqueio (não é servido), não
como um erro vermelho de falha.

### 4. Nada muda sob a cópia

A assinatura, o que ela cobre, a verificação e a condição de servir ficam como
`0003`/`0006`/`0010`/`0028`/`0047`/`0058` já decidiram. Este ADR é só a camada
de palavras: renomear não reabre nenhuma garantia nem portão.

## Consequências

- O operador lê, no selo, que a atestação é sobre a config, e vê o portão de
  segurança da tool como coisa separada, com nome próprio.
- As telas que hoje dizem "Signed/Unsigned/Sign" (lista de servidores, detalhe
  do backend, página de resultado do registro) passam a usar a cópia acima; a
  mudança é de template e de texto, sem lógica nova.

## Não cobre

- Qualquer mudança no significado, no alcance ou na verificação da assinatura:
  é só a cópia de interface.
