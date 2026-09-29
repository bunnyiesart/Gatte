# 0040. API de gestão e fronts opcionais

**Status:** Proposed — 29 set 2026. Vira Accepted quando a implementação
entrar; nesse commit, `0036` §1–§2 e `0038` §2 ganham a nota "revisto por
`0040`" e o README deixa de dizer que o `ui` roda como usuário de serviço.

## Contexto

O console web (`0036`) é um processo que chama os `run*` do CLI dentro de
si: a regra de aprovar, bloquear e editar contas está no mesmo pacote que
renderiza HTML. Isso deu uma implementação só de cada ação, mas amarrou três
coisas que o dono pediu para separar:

1. **O front tem de ser opcional.** Um host de produção que só roda `serve`
   e o CLI não precisa carregar templates, CSS nem o código de sessão web.
2. **Tem de haver um backend controlável**: uma superfície de gestão com
   contrato próprio, que outro programa possa chamar sem ler o banco nem o
   `config.toml`.
3. **Fronts alternativos**: o do Gatte e o de uma empresa que o implanta,
   cada um com a sua cara, sem que nenhum deles reimplemente uma regra.

O que não pode se perder no caminho é o que `0036`, `0038` e `0031` já
pagaram: aprovar só o fingerprint mostrado, uma linha de operador na trilha
para cada mudança, a conta do IdP fora do alcance do usuário de serviço,
senha de uso único só como hash, e as defesas de navegador de um servidor em
loopback.

## Decisão

### 1. `mcp-gateway admin`: HTTP/JSON sobre socket UNIX, e só isso

O backend é um subcomando do mesmo binário. Fala HTTP/1.1 com corpo JSON,
versionado em `/v1/...`, e escuta **apenas em socket UNIX**. Não existe flag
de TCP, nem de loopback, nem override. Um socket de arquivo tem dono, grupo e
modo; uma porta TCP em `127.0.0.1` é de todo usuário e de todo site aberto
no navegador (`0036` §Contexto), e ela não voltaria a existir aqui.

São **dois sockets, dois processos**:

| | Socket do operador | Socket de contas |
|---|---|---|
| Caminho padrão | `/run/mcp-gateway-admin/operator.sock` | `/run/mcp-gateway-admin/accounts.sock` |
| Processo | `mcp-gateway admin`, como o usuário de serviço | `mcp-gateway admin -accounts`, como root; recusa subir se não for root |
| Arquivo | `root:gatte-operators`, `0660` | `root:root`, `0600` (padrão) |
| Faz | tudo o que o console faz hoje, menos contas | contas do IdP (`0038`), e nada mais |

A regra de `0038` ("editar contas só num console root") passa a ser do
socket de contas: o processo que escreve `[idp] users_file` é root, e o
processo do usuário de serviço não tem essas rotas (404) nem o código que
escreve o arquivo aberto sobre ele. O socket de contas recusa, além disso,
qualquer par cujo uid seja o dono do banco do gateway (o usuário de
serviço), mesmo que o modo do arquivo tenha sido alargado por engano. Uma
implantação pode delegar contas a um grupo (`[admin] account_group`); o
padrão é só root.

Com `[admin] operator_group` configurado, o socket do operador recusa um par
que não seja root, nem o usuário de serviço, nem membro desse grupo. É a
segunda barreira atrás do modo do arquivo, pelo mesmo motivo.

### 2. Quem é o operador: o kernel diz, o cliente não

A identidade de operador na trilha vem da credencial do par no socket, lida
pelo kernel: `SO_PEERCRED` no Linux, `LOCAL_PEERCRED` (`getpeereid`) no
FreeBSD e no macOS. Nenhum campo, cabeçalho ou parâmetro da API diz quem é o
operador. `operatorName()` (`SUDO_USER`, `USER`) não é usado pelo backend.

- O uid vira nome pelo banco de contas do sistema, e a linha é
  `(operator:NOME)`, como hoje (`0031`).
- Quando o uid é uma conta compartilhada (0, ou o usuário de serviço) e o
  sistema é Linux, o backend lê `/proc/PID/loginuid` do par: é o uid de quem
  fez login, preservado pelo `sudo` e que um processo sem `CAP_AUDIT_CONTROL`
  não altera. Se ele existe e não é `4294967295`, a linha é atribuída a esse
  nome, e a razão ganha `[via root]` (ou `[via NOME-DO-SERVIÇO]`). Sem
  loginuid (FreeBSD, macOS, login direto de root), a linha fica com o nome
  da conta compartilhada, como já acontece no CLI (`0031` §4).
- Um uid sem nome no sistema é recusado (`peer_unattributable`): ação sem
  autor não é registro.

O cabeçalho opcional `Gatte-Front` (charset `[a-z0-9._-]`, até 32 bytes)
nomeia o front que chamou. É informativo e controlado pelo cliente, então
não decide nada: vira a marca que `0036` já grava, `[ui]` no front do Gatte,
`[NOME]` num outro, `[api]` quando ausente, no mesmo lugar da razão onde a
marca está hoje. O CLI dentro do processo não leva marca, como hoje.

### 3. Toda regra no backend

As operações saem de `cmd/mcp-gateway/ui*.go` e dos `run*` para
`internal/admin`, um serviço que devolve resultados tipados (os tipos de
`pkg/adminapi`) em vez de texto impresso. O CLI passa a ser um renderizador
desses resultados; a API, outro. Ficam no backend, e só nele:

- **Aprovar exige o fingerprint revisado**, comparado com a mesma leitura da
  entrada e escrito com compare-and-approve (`0032`). Sem fingerprint,
  `fingerprint_required`; outro fingerprint, `fingerprint_mismatch`; mudou no
  meio, `fingerprint_moved`. A revisão (definições, diff, code points
  escondidos, papéis que passam a poder chamar) é calculada no backend.
- **Toda mudança de estado grava uma linha de operador**: `(access block)`,
  `(access unblock)`, `(account …)` como hoje, e agora também
  `(tool approve)` e `(tool revoke)`, com servidor, tool e fingerprints na
  razão. Isso fecha o "quem aprovou fica fora da trilha" de `0032` e `0036`,
  inclusive para o CLI, que chama o mesmo serviço. Leituras e `audit verify`
  não gravam: uma linha nova mudaria o head que a verificação acabou de
  comparar.
- A ordem continua sendo mudar primeiro e registrar depois (`0031`); se a
  trilha falhar, a resposta é `audit_write_failed` com `applied: true`, e o
  front tem de mostrar que a mudança valeu.
- Grupos só de `[group_to_role]`; validação de conta; sugestão de username;
  senha de uso único gerada, mostrada uma vez na resposta (`no-store`) e
  gravada só como argon2id. Nenhum endpoint aceita senha.
- Listas são arrays JSON, nunca texto separado por vírgula.
- `keepDBOwner` depois de cada ação do processo root.
- O script de conexão (`0039`) é renderizado no backend, com as mesmas
  validações; o front recebe o texto pronto.
- Cada requisição relê o `config.toml`, como o `ui` fazia; arquivo que não
  carrega recusa a ação (`config_unavailable`). Mudanças são serializadas
  por um mutex, e o `retryBusy` do CLI vale aqui.
- Requisição com `Origin` ou `Cookie` é recusada (`browser_request_refused`):
  um front que repassasse o navegador direto ao socket perderia as defesas
  de `0036`, e isso tem de falhar alto.

Registrar, assinar e desregistrar backends continuam só no terminal, pelo
mesmo motivo de `0036` §2.

### 4. Sob demanda, sem processo sempre ligado

No Linux, cada socket é uma unidade `.socket` do systemd (`Accept=no`) com o
seu `.service`: o systemd cria o arquivo com dono, grupo e modo, e o backend
só sobe na primeira conexão. Ele encerra depois de `-idle` (padrão 5 min) sem
nenhuma conexão aberta; o socket fica, e a próxima conexão o sobe de novo. A
ativação é lida de `LISTEN_PID`/`LISTEN_FDS` sem dependência nova; um fd que
não seja `AF_UNIX`/`SOCK_STREAM` é recusado. Exemplos de unidade vão para
`examples/systemd/`.

Em primeiro plano (FreeBSD, macOS, teste): `mcp-gateway admin -socket PATH
[-socket-group G] [-socket-mode 0660] [-idle 0]`. O backend cria o socket,
recusa se o caminho existir e não for um socket, e aplica grupo e modo antes
de aceitar a primeira conexão. O diretório do socket não pode ser gravável
por grupo nem por outros; o backend recusa se for.

### 5. Pacotes públicos para quem escreve um front

- `pkg/adminapi`: os tipos de requisição e resposta, os códigos de erro e um
  `Client` que fala com o socket. Só a biblioteca padrão.
- `pkg/frontkit`: as defesas de navegador de `0036` §3 como biblioteca:
  checagem de bind e de `Host` em loopback, link de login de uso único que
  abre uma sessão presa ao caminho (`/s/ID/`) e a um cookie `HttpOnly`
  `SameSite=Strict`, token de formulário e `Origin` em todo POST, cabeçalhos
  (CSP `default-src 'none'`, `DENY`, `nosniff`, `no-referrer`, `no-store`),
  limite de corpo, e o escape visível (`internal/visible`) para todo texto
  que vem de backend, analista ou IdP.

A API devolve texto não confiável cru (JSON carrega qualquer coisa); o
contrato marca esses campos com `x-gatte-untrusted`, e escapá-los é dever do
front, com `frontkit`.

### 6. Fronts são clientes

- O front do Gatte vai para `internal/front/gatteweb` e só importa a
  biblioteca padrão, `pkg/adminapi` e `pkg/frontkit`. Um teste de fitness
  exige isso pelo grafo de imports: nenhum store, nenhum `run*`, nenhum
  `internal/config`. `mcp-gateway ui` passa a receber `-socket` e
  `-accounts-socket` em vez de `-config`, e roda como o próprio operador
  (membro de `gatte-operators`), não mais como o usuário de serviço.
  `-manage-users` passa a significar "abrir também o socket de contas", o
  que por padrão exige `sudo`.
- `-tags nofront` produz o binário sem `ui` e sem o pacote do front; `serve`,
  `admin` e o CLI funcionam iguais. O subcomando `ui` nesse binário diz que
  foi compilado sem front e sai com erro de uso. O `make ci` compila, testa
  e roda `vet` também com essa tag.
- Um front de terceiros é outro programa, em outro repositório, que importa
  os mesmos dois pacotes. O Gatte não carrega nenhum front além do seu.

### 7. Contrato e versão

O contrato é `api/admin.openapi.yaml` (OpenAPI 3.1), e o guia é
`docs/admin-api.md`. Dentro de `/v1` só entram mudanças aditivas: endpoint
novo, campo opcional novo, código de erro novo (o cliente trata um código
desconhecido pelo status HTTP). Remover, renomear ou mudar o sentido de um
campo é `/v2`, servido ao lado de `/v1` por pelo menos uma versão.
`GET /v1/whoami` devolve as versões da API que o processo serve.

## O que sai do front e o que fica

| Sai de `ui*.go` para o backend | Fica em cada front (via `frontkit`) |
|---|---|
| overview (o que precisa de atenção) | login de uso único, sessão, cookie |
| revisão e diff da tool, papéis que a cobrem | CSRF e `Origin` |
| aprovar e revogar | `Host` e bind em loopback, cabeçalhos |
| bloquear e desbloquear, com a marca do front | escape visível de todo texto não confiável |
| filtros e limite (5000) da trilha, verificar | layout, textos, navegação |
| People: papéis, grupos, quem já chamou | passos do assistente (GETs sem efeito) |
| contas, validação, sugestão de username, senha | mostrar a senha uma vez e não guardá-la |
| script de conexão | abas por sistema, botão de baixar |

## Consequências

- Um host pode rodar sem front nenhum; o console web deixa de ser um
  requisito para operar.
- O `ui` perde o acesso direto ao banco e ao `config.toml`. Quem roda o `ui`
  só tem o que o socket dá, e a trilha registra o usuário do sistema que o
  rodou, dito pelo kernel.
- Aprovar e revogar passam a aparecer na trilha. Quem conta linhas de
  operador no SIEM vê dois tipos novos.
- Dois processos a mais existem só enquanto alguém opera; em repouso o host
  tem dois arquivos de socket e duas unidades paradas.
- O CLI continua acessando o banco direto como usuário de serviço. É o mesmo
  serviço (`internal/admin`), então a regra é uma só, mas o CLI não passa
  pela credencial do socket: a atribuição dele continua sendo `operatorName`.
- Um front de terceiros é código que roda com o poder de um operador. O
  backend garante as regras; não garante que o front escape o que mostra
  nem que proteja a sessão. `frontkit` torna isso o caminho fácil, não o
  obrigatório.

## O que não resolve

- Operar de outra máquina continua sendo `ssh -L` até o front. A API não sai
  do host.
- Não há papéis dentro do console: quem abre o socket do operador tem todo o
  poder do operador. Separar "só leitura" de "aprova" seria um terceiro
  socket e fica para quando alguém pedir.
- No FreeBSD e no macOS não há loginuid: atrás de `sudo` a linha diz `root`.
- Sem ativação sob demanda fora do systemd; no FreeBSD o backend roda em
  primeiro plano ou por um rc.d escrito pela implantação.
- Registrar, assinar e desregistrar backends continuam fora da API.

## Testes

Escritos antes da implementação, cada um falhando no código de hoje:

- `internal/peercred`: o uid do par num socketpair real é o do processo; o
  loginuid é lido quando existe e ignorado quando é `4294967295`.
- `internal/admin`: aprovar sem, com outro e com o fingerprint mostrado;
  `fingerprint_moved` quando a definição muda entre a leitura e a escrita;
  aprovar e revogar gravam `(tool approve)` e `(tool revoke)`; bloqueio que
  não entra na trilha responde `audit_write_failed` com o bloqueio em vigor;
  grupo fora de `[group_to_role]` recusado; a senha não aparece em nenhuma
  linha da trilha.
- `internal/admin/adminhttp`: identidade vem do par e não de um campo;
  `Origin` e `Cookie` recusados; corpo com campo desconhecido recusado; rota
  de contas é 404 no socket do operador; socket de contas recusa o usuário de
  serviço; ativação recusa fd TCP; o processo sai depois de `-idle` sem
  conexão.
- `pkg/adminapi`: o cliente contra o servidor real, num socket temporário,
  cobre cada endpoint do contrato; um teste confere que toda rota registrada
  está em `api/admin.openapi.yaml` e vice-versa.
- `pkg/frontkit`: os casos de `0036` §Testes, agora na biblioteca.
- `internal/fitness`: `internal/front/gatteweb` não importa nada do módulo
  além de `pkg/adminapi` e `pkg/frontkit`; `-tags nofront` não traz o pacote
  do front para o binário.
- `cmd/mcp-gateway`: `admin -accounts` recusa fora do root; nenhuma flag
  abre TCP; o `ui` passa pelos testes de hoje falando com um backend real.
