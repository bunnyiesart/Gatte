# 0040. API de gestão e fronts opcionais

**Status:** Accepted — 29 set 2026. O backend (§1–§5 e §7: `mcp-gateway
admin`, `internal/admin`, `internal/peercred`, `pkg/adminapi`,
`pkg/frontkit`, `-tags nofront`) entrou primeiro; §6, o front do Gatte como
cliente da API (`internal/front/gatteweb`, `ui -socket`), entrou em seguida.
As diferenças entre o desenho e o que entrou estão em "Notas da
implementação", no fim.

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

São **dois sockets, dois processos, dois diretórios**:

| | Socket do operador | Socket de contas |
|---|---|---|
| Caminho padrão | `/run/mcp-gateway-admin/operator/operator.sock` | `/run/mcp-gateway-admin/accounts/accounts.sock` |
| Diretório | `operator/`, `0755`: do root (systemd) ou do usuário de serviço (primeiro plano) | `accounts/`, `root:root 0755` |
| Arquivo | `gatte-operators`, `0660` | `root:root 0600`, ou `root:ACCOUNT_GROUP 0660` |
| Processo | `mcp-gateway admin`, como o usuário de serviço | `mcp-gateway admin -accounts`, como root; recusa subir se não for root |
| Faz | tudo o que o console faz hoje, menos contas | contas do IdP (`0038`), e nada mais |

O pai, `/run/mcp-gateway-admin`, é `root:root 0755`. Cada socket tem o seu
diretório porque quem pode criar um arquivo num diretório pode apagar o
vizinho e pôr outro no lugar: com os dois juntos, o usuário de serviço
trocaria o socket de contas por um falso. O diretório decide quem pode
trocar o socket; quem pode conectar é decidido pelo grupo e pelo modo do
arquivo.

A regra de `0038` ("editar contas só num console root") passa a ser do
socket de contas, e ele segue três regras que fecham o caminho do usuário de
serviço até o root:

- **O processo root nunca abre nem muda dono de arquivo do usuário de
  serviço.** O banco do gateway, o `-wal` e o `-shm` ficam num diretório que
  o usuário de serviço grava; ele poderia trocar um deles por um link para
  `/etc/shadow`. A linha de trilha de uma ação de conta é escrita por um
  filho, `mcp-gateway admin -audit-writer`, iniciado com
  `SysProcAttr.Credential` no uid e gid do dono do diretório do banco (lido
  com `Lstat`; tem de ser um diretório e não pode ser root), sem grupos
  suplementares e com ambiente vazio. O filho recebe a linha pela entrada
  padrão, abre o banco como esse usuário, grava e sai; recusa rodar como
  root. `keepDBOwner` deixa de existir.
- **A configuração que o root lê é do root.** Antes de cada requisição,
  `admin -accounts` confere com `Lstat` o `config.toml`, o `[idp]
  users_file` e cada diretório acima deles até `/`: dono root, nenhum link
  simbólico, arquivo regular, sem escrita para grupo nem para outros. Se
  algum falhar, a resposta é `config_unavailable` dizendo qual caminho e
  por quê, e nada é escrito. Sem isso, quem grava o `config.toml` apontaria
  o `users_file` para qualquer arquivo, que o `tmp+rename` do
  `autheliafile` substituiria como root, ou alargaria o `account_group`.
- **O socket de contas recusa o usuário de serviço** (o dono do diretório do
  banco) mesmo que o modo do arquivo tenha sido alargado por engano.

Delegar contas a um grupo sem sudo exige as duas coisas: `[admin]
account_group` no `config.toml` e o arquivo do socket desse grupo com
`0660` (`SocketGroup`/`SocketMode` num override da unidade,
ou `-socket-group`/`-socket-mode` em primeiro plano). O backend compara os
dois ao subir e recusa um desencontro: grupo configurado com arquivo
`0600`, ou arquivo de um grupo que o `config.toml` não nomeia. É assim que o
`ui -manage-users` roda sem root.

O que a delegação entrega são as contas que o Gatte gerencia: uma conta
com pelo menos um grupo, todos em `[group_to_role]`. Trocar grupos,
desativar, ativar ou gerar senha de qualquer outra conta do IdP (o admin de
outras aplicações, uma pessoa sem grupo do Gatte) é recusado com
`account_not_managed`, porque a senha nova daria o login dela em todas as
aplicações atrás do IdP. Só um par que o kernel diz ser root (inclusive
atrás de `sudo`) alcança essas contas, como em `0038`. Tirar todos os
grupos de uma conta a põe fora do alcance do grupo; devolvê-la exige root.

Com `[admin] operator_group` configurado, o socket do operador recusa um par
que não seja root, nem o usuário de serviço, nem tenha esse grupo entre os
grupos que o kernel dá ao par (`SO_PEERGROUPS` no Linux, `cr_groups` de
`LOCAL_PEERCRED` no FreeBSD e no macOS). A barreira é o modo do arquivo; essa
checagem é a segunda, e não consulta o banco de grupos do sistema, que pode
discordar das sessões abertas.

Por isso o backend do operador confere o arquivo do socket ao subir, venha
ele do systemd ou de `-socket`: arquivo aberto a outros (`perm & 0007`)
recusa subir, e com `operator_group` configurado um arquivo aberto a grupo
tem de ser desse grupo. Um `SocketMode=0666` por engano admitiria todo uid
local como operador.

### 2. Quem é o operador: o kernel diz, o cliente não

A identidade de operador na trilha vem da credencial do par no socket, lida
pelo kernel no `accept`: `SO_PEERCRED` no Linux,
`unix.GetsockoptXucred(fd, 0, unix.LOCAL_PEERCRED)` no FreeBSD e no macOS
(`golang.org/x/sys`, já no grafo do módulo). Nenhum campo, cabeçalho ou
parâmetro da API diz quem é o operador. `operatorName()` (`SUDO_USER`,
`USER`) não é usado pelo backend.

- O uid vira nome pelo banco de contas do sistema, e a linha é
  `(operator:NOME)`, como hoje (`0031`).
- Quando o uid é 0 e o sistema é Linux, o backend lê o `loginuid` do par
  **uma vez, no `accept`**. Com `SO_PEERPIDFD` (Linux 6.5+), lê pelo pidfd e confere que
  o processo ainda vive depois da leitura; sem ele, lê `/proc/PID/loginuid`
  e confere que o `Uid` de `/proc/PID/status` é o uid do par. Se o pid pode
  ter sido reutilizado (a conferência falha) ou o valor é `4294967295`, a
  linha fica com `root`. Senão, é atribuída ao nome do loginuid, e a razão
  ganha `[via root]`.
- O usuário de serviço **não** é renomeado pelo loginuid. No Linux, um
  processo cujo loginuid não foi definido pode defini-lo sem privilégio
  (`audit_set_loginuid_perm`), e todo processo que o systemd sobe como
  usuário de serviço (o `serve`, um timer) está nessa situação: ele
  escreveria o uid de qualquer operador e teria a linha atribuída a ele.
  A linha de um par do usuário de serviço fica com o nome dele; o operador
  conecta como ele mesmo, membro de `gatte-operators`. O root poderia
  gravar a trilha direto, então o loginuid dele não abre nada novo.
- Sem loginuid (FreeBSD, macOS, login direto de root), a linha fica com o
  nome da conta compartilhada, como já acontece no CLI (`0031` §4).
- Um uid sem nome no sistema é recusado (`peer_unattributable`): ação sem
  autor não é registro.

O cabeçalho opcional `Gatte-Front` (charset `[a-z0-9._-]`, até 32 bytes)
nomeia o front que chamou. É informativo e controlado pelo cliente, então
não decide nada: vira a marca que `0036` já grava, `[ui]` no front do Gatte,
`[NOME]` num outro, `[api]` quando ausente, no mesmo lugar da razão onde a
marca está hoje.

O CLI dentro do processo passa a marcar as suas linhas, para que a trilha
distinga um nome dito pelo ambiente de um nome dito pelo kernel. No Linux o
CLI lê `/proc/self/loginuid` antes do ambiente e marca `[cli]` (com `[via
CONTA]` quando o loginuid nomeou outra pessoa); quando o nome veio de
`SUDO_USER`/`USER`, a marca é `[cli env]`. Isso vale para as linhas que o
CLI já grava (`access block`, contas) e para as novas `tool approve` e
`tool revoke`.

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
- **O texto de revisão sai em segmentos calculados dos bytes crus.** Nome,
  descrição, linhas da definição e diff vêm como `{raw, segments}`, e cada
  segmento é texto, um code point escondido (`U+202E`) ou um byte que não é
  UTF-8 (`FF`), que o JSON não carregaria. As linhas do diff trazem `op` e
  segmentos, sem o prefixo `+ `/`- ` nem o recuo de exibição; o corte de
  rótulo solto no fim de um trecho, que o `ui` fazia, é feito aqui. Um front
  só desenha segmentos; nunca reinterpreta texto já escapado, onde um
  `\u{202E}` literal e um U+202E de verdade seriam iguais.
- **Toda mudança de estado grava uma linha de operador**: `(access block)`,
  `(access unblock)`, `(account …)` como hoje, e agora também
  `(tool approve)` e `(tool revoke)`, com servidor, tool e fingerprints na
  razão. Isso fecha o "quem aprovou fica fora da trilha" de `0032` e `0036`,
  inclusive para o CLI, que chama o mesmo serviço. Leituras e `audit verify`
  não gravam: uma linha nova mudaria o head que a verificação acabou de
  comparar.
- **Mudança feita nunca some da resposta.** A ordem continua sendo mudar
  primeiro e registrar depois (`0031`). Se a trilha falhar depois de a
  mudança valer, a resposta é o 2xx normal da operação, com `recorded:
  false`, sem `audit`, e o aviso `audit_write_failed`; a senha de uso único,
  a tool aprovada e os papéis vêm como sempre. Um erro que perdesse a senha
  de um `reset-password` já aplicado trancaria a pessoa fora, e cada nova
  tentativa bateria na mesma trilha quebrada.
- **Repetir é seguro onde o contrato diz.** Aprovar, revogar, bloquear,
  desbloquear, trocar grupos, desativar e ativar são idempotentes (a
  repetição responde `changed: false`). Criar conta não é: depois de um
  `internal` ou de uma conexão cortada, o front consulta a conta antes de
  tentar de novo, e se ela existir gera outra senha com `reset-password`.
  Cada `reset-password` invalida a senha anterior.
- Grupos só de `[group_to_role]`; validação de conta; sugestão de username;
  senha de uso único gerada, mostrada uma vez na resposta e gravada só como
  argon2id. Nenhum endpoint aceita senha. A senha aparece em exatamente um
  campo da resposta, `one_time_password`: nunca em `messages`, `warnings`,
  mensagens de erro, na trilha nem no log do backend. O `Cache-Control:
  no-store` do backend é informativo num socket UNIX; o que protege o
  navegador é o `no-store` que o `frontkit` sempre manda.
- Listas são arrays JSON, nunca texto separado por vírgula. Tudo o que um
  front decide ou traduz tem chave de máquina: `Overview.problems` é
  `{code, part, message}`, `Connect.missing` é a lista de chaves de
  `[connect]` que faltam, e `Attention.kind` é a chave de tradução, com
  `detail` só como texto de reserva.
- O script de conexão (`0039`) é renderizado no backend, com as mesmas
  validações; o front recebe o texto pronto.
- Cada requisição relê o `config.toml`, como o `ui` fazia; arquivo que não
  carrega, ou que no socket de contas não passa pela checagem de dono do
  §1, recusa a ação (`config_unavailable`).
- O corpo é lido, decodificado e validado **antes** do mutex que serializa
  as mudanças. Dentro dele, o `retryBusy` do CLI vale, limitado pelo prazo
  da requisição.
- Requisição com `Origin` ou `Cookie` é recusada (`browser_request_refused`):
  um front que repassasse o navegador direto ao socket perderia as defesas
  de `0036`, e isso tem de falhar alto. Não é a defesa principal (um proxy
  pode tirar os dois); a principal é `frontkit` (§5) e, no front de uma
  empresa, um teste de fitness no repositório dela.

Registrar, assinar e desregistrar backends continuam só no terminal, pelo
mesmo motivo de `0036` §2.

### 4. Sob demanda, sem processo sempre ligado

No Linux, cada socket é uma unidade `.socket` do systemd (`Accept=no`) com o
seu `.service`: o systemd cria o arquivo com dono, grupo e modo, e o backend
só sobe na primeira conexão. A ativação é lida de `LISTEN_PID`/`LISTEN_FDS`
sem dependência nova; um fd que não seja `AF_UNIX`/`SOCK_STREAM` é recusado.
Exemplos de unidade, e o override de `account_group`, vão para
`examples/systemd/`.

O processo encerra depois de `-idle` (padrão 5 min) **sem requisição em
andamento e sem nenhuma completada nesse tempo**; conexões abertas e
ociosas não o seguram e são fechadas na saída. O socket fica, e a próxima
conexão o sobe de novo. Para que um par lento não prenda o processo nem os
outros operadores: `ReadHeaderTimeout` 5 s, `ReadTimeout` 10 s,
`WriteTimeout` 30 s, `IdleTimeout` 30 s, `MaxHeaderBytes` 16 KiB, corpo até
64 KiB, e no máximo 16 conexões simultâneas (a 17ª é fechada no accept).

Em primeiro plano (FreeBSD, macOS, teste): `mcp-gateway admin -socket PATH
[-socket-group G] [-socket-mode 0660] [-idle 0]`. O backend cria o socket,
recusa se o caminho existir e não for um socket, e aplica grupo e modo antes
de aceitar a primeira conexão. Ele confere, com `Lstat`, o diretório do
socket e cada um acima dele até `/`: nenhum link simbólico, nenhum gravável
por grupo ou outros, todos os acima do diretório do socket do root, e o
diretório do socket do root ou (só no socket do operador) do próprio
usuário do processo. Não confere só os bits de modo: um diretório `0755` do
usuário de serviço também deixaria ele trocar o socket.

O cliente confere do seu lado quem serve. `pkg/adminapi` lê a credencial do
servidor depois de conectar (`SO_PEERCRED` e `LOCAL_PEERCRED` funcionam
também no lado do cliente) e recusa um socket de contas cujo servidor não
seja uid 0 (`ErrImpostor`). No socket do operador, `WithServerUID` fixa os
uids aceitos. Sob o systemd, o servidor que o kernel informa é quem criou o
socket, o systemd, uid 0; em primeiro plano é o próprio backend.

### 5. Pacotes públicos para quem escreve um front

- `pkg/adminapi`: os tipos de requisição e resposta, os códigos de erro e um
  `Client` que fala com o socket, confere o servidor (§4) e omite campos
  opcionais com valor zero. O `Client` não tem como receber cabeçalhos
  arbitrários: não há caminho para repassar os do navegador. Usa a
  biblioteca padrão e `golang.org/x/sys/unix` para a credencial.
- `pkg/frontkit`: as defesas de navegador de `0036` §3 como biblioteca, com
  uma porta de entrada só: `frontkit.New(cfg)`, que faz o bind, e
`kit.Serve(mux)`. Não há
  `Handler` exportado para montar à mão; servir por outro caminho é não usar
  `frontkit`. Dentro: checagem de bind e de `Host` em loopback, link de
  login de uso único que abre uma sessão presa ao caminho (`/s/ID/`) e a um
  cookie `HttpOnly` `SameSite=Strict`, token de formulário e `Origin` em
  todo POST, cabeçalhos (CSP `default-src 'none'`, `DENY`, `nosniff`,
  `no-referrer`, `no-store` sempre), limite de corpo, e o desenho dos
  segmentos que o backend manda (§3), além do escape visível para texto que
  o próprio front tenha.

**Toda string de toda resposta é não confiável**: vem de um backend MCP, de
um analista, do IdP, de um `users_file` editado à mão ou de um
`config.toml`. O contrato não marca campo a campo, porque uma marcação
incompleta ensinaria que o resto é seguro. Um front escapa tudo para o seu
meio (HTML, terminal, chat) e torna visíveis os code points escondidos.

### 6. Fronts são clientes

- O front do Gatte vai para `internal/front/gatteweb` e só importa a
  biblioteca padrão, `pkg/adminapi` e `pkg/frontkit`. Um teste de fitness
  exige isso pelo grafo de imports: nenhum store, nenhum `run*`, nenhum
  `internal/config`. `mcp-gateway ui` passa a receber `-socket` e
  `-accounts-socket` em vez de `-config`, e roda como o próprio operador
  (membro de `gatte-operators`), não mais como o usuário de serviço.
  `-manage-users` passa a significar "abrir também o socket de contas": com
  `account_group` delegado (§1), o operador desse grupo roda o front sem
  root; sem delegação, exige `sudo`.
- `-tags nofront` produz o binário sem `ui` e sem o pacote do front; `serve`,
  `admin` e o CLI funcionam iguais. O subcomando `ui` nesse binário diz que
  foi compilado sem front e sai com erro de uso. O `make ci` compila, testa
  e roda `vet` também com essa tag.
- Um front de terceiros é outro programa, em outro repositório, que importa
  os mesmos dois pacotes. O Gatte não carrega nenhum front além do seu. O
  repositório da implantação que tiver um front web próprio leva um teste de
  fitness equivalente: o front serve só por `kit.Serve` e não chama
  `http.Serve`/`ListenAndServe` por fora dele.

### 7. Contrato e versão

O contrato é `api/admin.openapi.yaml` (OpenAPI 3.1), e o guia é
`docs/admin-api.md`. `info.version` é a revisão do contrato (semver:
`1.MENOR.CORREÇÃO` dentro de `/v1`), e `GET /v1/whoami` devolve essa
revisão e uma lista de `features` (nomes estáveis, um por capacidade que
entrou depois de `1.0`).

Dentro de `/v1` só entram mudanças aditivas: endpoint novo, campo novo na
resposta, valor novo em enum de resposta ou em código de erro, campo
opcional novo na requisição. Um front ignora campo desconhecido e tem ramo
padrão em todo enum e código. O backend recusa campo desconhecido na
requisição (um `fingerprint` com erro de digitação não pode ser ignorado),
então o compatível é assim: o `Client` omite campo opcional com valor zero,
e um front só manda um campo novo depois de ver a `feature` dele no
`whoami`. Rota inexistente é `unknown_route` (backend mais antigo, ou
caminho errado), rota do outro socket é `wrong_socket` com
`details.socket`, e `not_found` fica só para tool, conta ou bloqueio que não
existe.

Remover, renomear ou mudar o sentido de um campo é `/v2`, servido ao lado de
`/v1` por pelo menos uma versão.

> **CORREÇÃO — 29 set 2026 (ADR-0041).** O contrato está em `1.1.0`, e
> `features` deixou de ser vazio: o backend lista `maintenance` e serve
> `GET /v1/maintenance`, `POST /v1/maintenance/on` e
> `POST /v1/maintenance/off`, que escrevem as linhas de operador
> `(maintenance on)` e `(maintenance off)` (grava primeiro, registra depois,
> `recorded: false` se a trilha falhar). `not_found` passou a valer também
> para um backend não registrado numa manutenção. `backend_health` (`health`
> no `Overview` e em cada `Upstream`) está no contrato e **ainda não é
> servido**, por isso ainda não aparece em `features`.

> **CORREÇÃO — 29 set 2026, segunda etapa da ADR-0041.** `backend_health`
> passa a ser servido e a constar em `features`, ao lado de `maintenance`.
> O `Overview` e cada `Upstream` levam `health`, lido das tabelas que o
> `serve` escreve (`backend_health`, `serve_status`) e da `maintenance`: o
> backend de gestão continua sem enxergar a memória do `serve`. O `serve`
> conta como `not_reporting` quando a última rodada é mais velha que duas
> vezes o intervalo mais o `reconcileTimeout` (`Deps.ServeGrace`), e então
> todo backend fora de manutenção é `unknown`. No `Overview`, um `health`
> ilegível é um `problem` de parte `health` (ou `maintenance`); na lista de
> `Upstreams`, é logado e a lista sai sem `health`, porque o que ela
> responde é o registro. O CLI (`upstream maintenance`, `maintenance`) e o
> front do Gatte (página Backends, formulário com CSRF) chamam o mesmo
> `admin.Service`.

> **CORREÇÃO — 30 set 2026 (ADR-0043).** O contrato está em `1.2.0`, com a
> feature `tool_review_set`: `GET /v1/tools/review-set` e
> `POST /v1/tools/approve-set` aprovam o conjunto de revisão de um backend
> por manifesto, tudo ou nada, com uma linha `(tool approve)` por ferramenta
> e uma `(tool approve set)`; códigos novos `manifest_required` e
> `manifest_mismatch`. A regra do §3 continua a mesma, para um conjunto:
> aprova-se só o que foi mostrado.

## O que sai do front e o que fica

| Sai de `ui*.go` para o backend | Fica em cada front (via `frontkit`) |
|---|---|
| overview (o que precisa de atenção) | login de uso único, sessão, cookie |
| revisão e diff da tool, em segmentos, e papéis que a cobrem | CSRF e `Origin` |
| aprovar e revogar | `Host` e bind em loopback, cabeçalhos |
| bloquear e desbloquear, com a marca do front | desenhar segmentos, escapar todo texto |
| filtros, limite (5000) e paginação da trilha, verificar | layout, textos, tradução, navegação |
| People: papéis, grupos, quem já chamou | passos do assistente (GETs sem efeito) |
| contas, validação, sugestão de username, senha | mostrar a senha uma vez e não guardá-la |
| script de conexão | abas por sistema, botão de baixar |

## Consequências

- Um host pode rodar sem front nenhum; o console web deixa de ser um
  requisito para operar.
- O `ui` perde o acesso direto ao banco e ao `config.toml`. Quem roda o `ui`
  só tem o que o socket dá, e a trilha registra o usuário do sistema que o
  rodou, dito pelo kernel.
- Aprovar e revogar passam a aparecer na trilha, e as linhas do CLI ganham
  `[cli]` ou `[cli env]`. Quem conta ou filtra linhas de operador no SIEM
  vê dois tipos novos e uma marca nova.
- Dois processos a mais existem só enquanto alguém opera; em repouso o host
  tem dois arquivos de socket e duas unidades paradas. Uma ação de conta
  custa um processo filho curto a mais (`-audit-writer`).
- A implantação passa a ter de manter `config.toml`, `users_file` e os
  diretórios acima deles do root e sem escrita para grupo ou outros; o
  `admin -accounts` recusa trabalhar de outro jeito. O README de implantação
  de quem usa o Gatte diz os modos.
- O CLI continua acessando o banco direto como usuário de serviço. É o mesmo
  serviço (`internal/admin`), então a regra é uma só, mas o CLI não passa
  pela credencial do socket; a marca diz de onde veio o nome.
- Um front de terceiros é código que roda com o poder de um operador. O
  backend garante as regras; não garante que o front escape o que mostra
  nem que proteja a sessão. `frontkit` e o teste de fitness no repositório
  do front fecham isso por construção, não por convenção.

## O que não resolve

- Operar de outra máquina continua sendo `ssh -L` até o front. A API não sai
  do host.
- Não há papéis dentro do console: quem abre o socket do operador tem todo o
  poder do operador. Separar "só leitura" de "aprova" seria um terceiro
  socket e fica para quando alguém pedir.
- No FreeBSD e no macOS não há loginuid: atrás de `sudo` a linha diz `root`.
- O CLI ainda não fala com o socket do operador quando ele existe; até lá,
  a atribuição dele fora do Linux é a do ambiente, marcada `[cli env]`.
- Sem ativação sob demanda fora do systemd; no FreeBSD o backend roda em
  primeiro plano ou por um rc.d escrito pela implantação.
- Registrar, assinar e desregistrar backends continuam fora da API.
- O CLI rodado como usuário de serviço ainda lê o próprio loginuid
  (`[cli]`), que esse processo poderia ter definido; a marca vale o que o
  CLI sempre valeu, e o usuário de serviço grava o banco de qualquer jeito.

## Testes

Escritos antes da implementação, cada um falhando no código de hoje:

- `internal/peercred`: o uid e os grupos do par num socketpair real são os
  do processo, dos dois lados da conexão; o loginuid é lido no accept,
  ignorado quando é `4294967295` e descartado quando o `Uid` do
  `/proc/PID/status` não confere.
- `internal/admin`: aprovar sem, com outro e com o fingerprint mostrado;
  `fingerprint_moved` quando a definição muda entre a leitura e a escrita;
  aprovar e revogar gravam `(tool approve)` e `(tool revoke)`; bloqueio e
  `reset-password` com a trilha quebrada respondem 2xx com `recorded:
  false`, o aviso `audit_write_failed` e, no reset, a senha; grupo fora de
  `[group_to_role]` recusado; a senha aparece uma vez só no corpo inteiro
  da resposta e nunca na trilha, em `messages`, em `warnings` nem no log do
  backend; segmentos de uma descrição com U+202E, com `\u{202E}` literal e
  com um byte `FF` saem diferentes entre si.
- `internal/admin` (contas): um `-wal` trocado por link para um arquivo do
  root não é aberto nem tem dono mudado pelo processo root; o
  `-audit-writer` recusa rodar como root; `config.toml`, `users_file` ou um
  diretório acima deles gravável pelo grupo, de outro dono ou link
  simbólico dá `config_unavailable` sem escrever nada; `account_group` com
  socket `0600` recusa subir.
- `internal/admin/adminhttp`: identidade vem do par e não de um campo;
  `Origin` e `Cookie` recusados; corpo com campo desconhecido recusado; rota
  de contas no socket do operador é `wrong_socket`, rota inexistente é
  `unknown_route`; socket de contas recusa o usuário de serviço; ativação
  recusa fd TCP; o processo sai depois de `-idle` com uma conexão aberta e
  parada; um corpo lento não segura o mutex de outro operador; a 17ª
  conexão é fechada; diretório do socket do usuário de serviço acima do
  diretório do socket é recusado.
- `pkg/adminapi`: o cliente contra o servidor real, num socket temporário,
  cobre cada endpoint do contrato; um servidor impostor (uid que não é o
  esperado) no caminho do socket de contas é recusado pelo cliente; campo
  opcional zero não vai no corpo; um teste confere que toda rota registrada
  está em `api/admin.openapi.yaml` e vice-versa.
- `pkg/frontkit`: os casos de `0036` §Testes, agora na biblioteca, e
  `no-store` em toda resposta.
- `internal/fitness`: `internal/front/gatteweb` não importa nada do módulo
  além de `pkg/adminapi` e `pkg/frontkit` e serve só por `kit.Serve`;
  `-tags nofront` não traz o pacote do front para o binário.
- `cmd/mcp-gateway`: `admin -accounts` recusa fora do root; nenhuma flag
  abre TCP; as linhas do CLI levam `[cli]` ou `[cli env]`; o `ui` passa
  pelos testes de hoje falando com um backend real.

## Notas da implementação

O que a implementação decidiu além do texto acima, ou mudou nele:

- `mcp-gateway admin` sem `-accounts` recusa rodar como root: o socket do
  operador é do usuário de serviço, e um processo root que abrisse o banco
  deixaria `-wal` e `-shm` do root.
- `access unblock` segue `0031`: grava a linha e depois solta. Se a trilha
  falhar, nada mudou, e a resposta é um erro, não um 2xx com `recorded:
  false`; esse só existe para mudança que já vale.
- `-audit-writer` só acrescenta linha de conta: `(operator:…)`,
  `(gateway)`, `allowed` e uma das cinco `(account …)`. Não é um caminho
  para escrever outra linha na trilha como o usuário de serviço.
- A credencial do par está em `internal/peercred`, usado pelo backend e
  pelo `pkg/adminapi`. No Linux, com `SO_PEERPIDFD`, o pidfd é conferido
  vivo depois da leitura do loginuid; sem ele, vale só a conferência do
  `Uid` de `/proc/PID/status`.
- Cada requisição tem prazo de 25 s (`RequestDeadline`), dentro do
  `WriteTimeout`, e é ele que limita o `retryBusy` do serviço.
- A trilha da API é paginada pela posição na cadeia (ordem de inserção),
  a mesma do `audit -verify`; o `audit` do CLI continua por timestamp.
- Trocar grupos para os mesmos, desativar uma conta desativada e ativar
  uma ativa respondem `changed: false` e não gravam linha.
- O `pkg/frontkit` saiu do `ui.go`. Na conversão de §6 o `ui` perdeu a
  própria cópia das defesas, o `keepDBOwner` e o diff por texto
  (`uiDiffHunks`): a página desenha os trechos e os segmentos de
  `ToolReview`, e o prefixo `+ `/`- ` e o recuo da definição são postos
  pelo front na hora de desenhar.
- §6, como entrou: `internal/front/gatteweb` recebe um `*adminapi.Client`
  do socket do operador, um do socket de contas (nulo sem
  `-manage-users`, e as páginas de conta são 404) e o `*frontkit.Kit`, e
  serve por `f.kit.Serve`. O `cmd/mcp-gateway/ui.go` só liga isso: cria o
  kit, chama `whoami` no socket do operador (sem backend, diz como subir e
  sai antes de imprimir o link), abre o de contas com `NewAccounts` (que
  recusa servidor que não seja root) e imprime o nome que o backend deu ao
  operador. `-config` é recusado com o caminho do socket.
- Os testes de fitness são três (`internal/fitness/front_test.go`): o grafo
  de imports do front (só a biblioteca padrão, `pkg/adminapi` e
  `pkg/frontkit`, e nenhuma dependência transitiva em store, config ou
  serviço), os arquivos `ui*.go` do comando (os mesmos imports, e nenhum
  `run*`, `opEnv`, `loadConfig` ou `openStore`), e que nenhum arquivo de front
  abra listener ou `http.Server` fora do `kit.Serve`.
- O `frontkit.DrawSegments` marca o code point escondido com
  `title="Hidden character"`, como a página já fazia.
- Criar conta não é idempotente: se a resposta se perde, o front consulta a
  conta e, se ela existe, diz que a senha se perdeu com a resposta e manda
  gerar outra (Reset password), sem tentar de novo por conta própria.
- Os testes do `ui` rodam contra um backend real (`adminhttp` sobre o banco
  do teste) num socket temporário, e o front por HTTP de verdade num porto
  de loopback. O socket de contas do teste é do usuário do teste, então o
  teste o abre com o cliente do operador; o `NewAccounts` recusaria. A
  recusa é o próprio teste `TestUI_ManageUsersRefusesAnAccountsSocketNotServedByRoot`.
- Não exercitado ainda: o backend de contas de ponta a ponta como root (a
  troca de credencial do `-audit-writer` e o caminho do systemd). Precisa
  de um teste numa VM Linux como root.
- O contrato é conferido por
  `TestContract_EveryDocumentedOperationIsServedAndEveryServedRouteIsDocumented`
  e `TestClient_CoversEveryOperationOfTheContractAgainstTheRealBackend`; a
  atribuição pelo kernel por
  `TestIdentity_ComesFromThePeerAndNotFromTheRequest`.
- Correções da revisão de segurança:
  - `account_not_managed` (§1): grupos, desativar, ativar e
    `reset-password` só alcançam contas cujos grupos estão todos em
    `[group_to_role]` (e ao menos um), a menos que o par seja root.
    `TestAccounts_ADelegatedOperatorReachesOnlyAccountsGatteManages` e
    `TestAccounts_ARootPeerReachesEveryAccount`.
  - O loginuid só renomeia par root (§2):
    `TestLoginUID_NamesOnlyARootPeer`.
  - O socket do operador aberto a outros, ou de outro grupo que o
    `operator_group`, recusa subir (§1):
    `TestOperatorSocket_AFileOpenToOthersRefusesToStart` e
    `TestAdmin_TheOperatorBackendRefusesASocketOpenToEveryone`.
  - `/v1/audit` pagina no banco (`Recorder.Page`: com ids 1..COUNT, a
    posição é o id e os filtros vão para o `WHERE`; com lacuna, percorre do
    mais novo contando a posição) e `/v1/people` agrega com `GROUP BY`
    (`Recorder.Analysts`); nenhum dos dois carrega a trilha inteira. O
    `last_call` de People passa a ser o timestamp da linha mais nova da
    identidade. `TestAuditAndPeople_DoNotReadTheWholeTrail`,
    `TestPage_MatchesTheChainPositionsWithAndWithoutAGap`.
  - O `users_file` mantém dono e grupo a cada reescrita: a unidade de
    contas tem `CAP_CHOWN`, e sem o privilégio o `autheliafile` recusa a
    troca em vez de deixar um arquivo que o IdP não lê.
    `TestWrite_RefusesToReplaceAFileWhoseOwnerItCannotKeep`,
    `TestSystemdUnits_TheAccountsBackendCanKeepTheUsersFilesGroup`.
  - Em primeiro plano o `-idle` padrão é 0 (nunca sai); o de 5 min vale só
    para o socket ativado pelo systemd.
    `TestAdmin_TheForegroundBackendDoesNotExitWhenIdle`.
  - As unidades gravam onde o `config.example.toml` grava
    (`/var/db/mcp-gateway`, `/var/log/mcp-gateway`).
    `TestSystemdUnits_WriteWhereTheExampleConfigurationWrites`.
  - O motivo guardado no bloqueio leva a marca do ator (`[cli] motivo`,
    `[ui] motivo`), e é essa a coluna REASON do `access list`; a checagem
    antecipada do CLI valida o motivo já marcado.
    `TestAccessBlock_TheEarlyCheckValidatesTheReasonTheServiceStores`.
