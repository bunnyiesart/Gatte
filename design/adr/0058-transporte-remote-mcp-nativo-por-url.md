# 0058. Transporte `remote`: um MCP nativo alcançado por URL, com conexão viva, assinatura só do endpoint e egresso guardado

**Status:** Accepted — 10 nov 2026. Acrescenta um quarto transporte ao lado
de `stdio`, `oci` (`0028`) e `http` (`0047`/`0048`). Reaproveita a quarentena
por tool (`0007`/`0013`), os portões do `Dispatch` (`0035`), a trilha
record-then-forward (`0012`), o `scrubResult` (`0047` §5) e a saúde/redial de
conexão viva (`0024`/`0041`) sem mudar nenhum deles. Anota o `0033` (egresso
dos backends), cujo alcance este transporte não estende, e declara a lacuna.

## Contexto

O Gatte hoje serve três transportes, e nenhum alcança um servidor que **já
fala MCP** por HTTP:

- `stdio` (`0028` §A) e `oci` (`0028`) falam MCP de verdade, por um cano
  local, com `mcp.CommandTransport` do go-sdk: o gateway spawna um processo
  (ou um container que é um filho stdio) e mantém uma conexão viva com ele.
- `http` (`0047`/`0048`) **não** fala MCP: ingere um OpenAPI, sintetiza uma
  tool por operação e, a cada chamada, monta um pedido REST sem estado. Não há
  conexão viva, e a saúde é um `up` fixo.

Falta o caso do meio: um servidor MCP nativo, operado por outra equipe ou por
um fornecedor, que o analista alcança por uma URL e que anuncia as próprias
tools pelo protocolo. O go-sdk v1.8.0 já traz os dois transportes de cliente
para isso — `SSEClientTransport` e `StreamableClientTransport` — e nenhum é
usado hoje.

O dono aprovou (10 nov 2026) adicionar esse backend pela URL, no console e na
CLI. Este ADR fixa o transporte; o `0059` cobre como ele entra pelo console.

## Decisão

### 1. Um quarto transporte: `remote`

`registry.Transport` ganha `TransportRemote = "remote"`. O composition root
(`cmd/mcp-gateway/dialer.go`) ganha um quarto `case` no `switch` que já escolhe
entre `stdio`, `oci` e `http`, roteando para um adaptador novo. O `default`
continua recusando qualquer outro valor, e a mensagem passa a nomear os quatro.

O nome é `remote` e não `http` de propósito: `http` já significa "REST
ingerido de OpenAPI" (`0047`). `remote` significa "um MCP nativo, vivo, por
URL". Na tela o substantivo é **"Remote MCP server (URL)"** (`0059`).

### 2. Um adaptador novo, com a forma do `stdio`, não a do `resthttp`

`internal/gateway/remotemcp` implementa `gateway.Dialer`/`gateway.Upstream`
(as interfaces de `internal/gateway/gateway.go`). Ele **espelha o
`internal/gateway/stdio`**, não o `internal/gateway/resthttp`:

- `Dial` abre uma `mcp.Client` sobre o transporte de cliente escolhido (item
  3) e guarda a `ClientSession` viva, como o `stdio` guarda a sessão sobre
  `mcp.CommandTransport`.
- `ListTools` e `CallTool` delegam à sessão viva.
- `Close` encerra a sessão.
- Reporta `ErrUpstreamGone` quando o stream cai, para que o `Reconcile`/redial
  do `0024` feche e rediscague, igual ao `stdio`.

Não é a forma do `resthttp` (sem estado, sem conexão, um segredo reresolvido
por chamada): um MCP nativo é uma conexão viva, com handshake e lista de
tools, que a quarentena observa — exatamente o modelo de `stdio`/`oci`.

### 3. Streamable HTTP agora; SSE declarado e adiado

O transporte de cliente é escolhido por um campo da entrada (`remote_kind`).
Dos dois que o SDK oferece:

- **Streamable HTTP** (`StreamableClientTransport`) é o transporte atual do
  protocolo: a especificação de 2025-03-26 o adotou no lugar do antigo
  HTTP+SSE. **É o que este ADR manda construir e é o padrão.**
- **SSE** (`SSEClientTransport`) é o transporte legado, que o SDK ainda traz
  para servidores antigos. **Fica declarado e adiado:** o campo `remote_kind`
  reserva o valor `sse`, e o adaptador o liga quando um backend real e legado
  o exigir. Construir os dois agora, sem um servidor SSE para provar contra,
  seria código sem exercício (KISS).

Um `remote_kind` ausente é `streamable`; `sse` é recusado no `Validate`
enquanto não for construído, com a mensagem dizendo que é um caminho adiado, e
não um erro de digitação.

### 4. Registro: `Validate` para `remote`

Uma entrada `remote`:

- **exige** `URL` bem-formada (esquema/host/porta/caminho), como a `http`;
- **proíbe** `Command` e `Image`, como a `http` proíbe `Command`;
- **proíbe** `Operations`: um MCP nativo anuncia as próprias tools, que a
  quarentena observa ao vivo — não há conjunto de operações congelado a
  guardar, ao contrário da `http` (§3 de `0047`);
- **permite** `EnvVarNames` com **um** nome, a referência do segredo de auth
  (item 6), pela mesma regra da `http`;
- **permite** o descritor de auth (`AuthKind`/`AuthName`) e exige o
  `remote_kind` (item 3).

É a mesma disciplina do `Validate` atual: um campo sem efeito sobre o que roda
é recusado, para não ser assinado sem significar nada.

### 5. Assinatura: uma tag canônica nova, do endpoint, sem digest de operações

`internal/signer` ganha a tag `mcp-gateway/signer/canonical/v4-remote`, ao
lado de `v1`, `v2-image` (`0028` §C) e `v3-http` (`0047` §4). Ela cobre:

- a **URL inteira** (esquema, host, porta, caminho), não só o host;
- o **descritor de auth** (`AuthKind`, `AuthName`);
- o **`remote_kind`**, porque ele decide qual protocolo de fio alcança o
  endpoint, e trocá-lo é uma mudança que o operador atesta;
- tudo o que a `v1` já cobre (Name, Transport, Command vazio mas no layout,
  Args, EnvVarNames ordenados).

**Não** cobre um digest do conjunto de operações, ao contrário da `v3-http`:
não há conjunto congelado (item 4), então a `v4-remote` é mais simples que a
`v3-http` por construção. Como as demais, é uma tag separada, prefixada por
comprimento: os layouts nunca coincidem, então uma assinatura `v1`/`v2`/`v3`
nunca autentica uma entrada `remote`, e uma entrada `remote` que perca a URL,
o descritor ou o `remote_kind` por escrita direta no banco deixa de verificar
em vez de manter a assinatura antiga. Repontar a URL de um endpoint aprovado,
ou virar o `AuthKind` de um cabeçalho para outro lugar, quebra a assinatura.

### 6. Auth: token estático do cofre, resolvido na conexão, mascarado na volta

O segredo de auth é um **bearer/header estático**, resolvido do cofre **no
`Dial`** (uma vez por conexão, como `stdio`/`oci` resolvem o ambiente no
spawn — e ao contrário da `http`, que reresolve por chamada porque não tem
conexão). O adaptador guarda a localização (`AuthKind`/`AuthName`) e injeta o
valor no cabeçalho de cada pedido do cliente MCP; o valor nunca é persistido,
logado nem citado em erro, pela mesma regra do `stdio`.

- **Mascaramento:** o `scrubResult` do `Dispatch` (`0047` §5, passo 7), que já
  troca uma credencial injetada que o upstream devolva por um marcador, vale
  para `remote` sem mudança, porque é um passo do `Gateway`, não do adaptador.
- **Token-passthrough é proibido (MUST):** o gateway usa **o seu próprio**
  token para o endpoint remoto e **nunca** encaminha a credencial do analista.
  Isto é estrutural, não um passo: `access.Identity` não tem campo de token
  (AGENTS.md §2, "Credential stripping is structural"). **Bearer estático
  primeiro; OAuth depois** fica declarado e adiado (`DEVELOPMENT-LOG.md` §9.1,
  o MUST de cunhar o próprio token quando/se um endpoint OAuth existir).

### 7. Egresso: a mesma guarda do `resthttp` para o salto gateway→remoto

O salto do gateway até o endpoint remoto passa pela guarda de SSRF/egresso que
o `resthttp` já tem (`internal/gateway/resthttp/egress.go`, `0048` §6):

- allowlist de host e **pinagem de redirecionamento** (o cliente é fixado ao
  host assinado; um 3xx para outro host é recusado);
- **recusa no IP resolvido** (`refuseAddr`/`controlCheck`): loopback, privado,
  link-local (que inclui o endpoint de metadados), CGNAT e os embutidos
  IPv4-em-IPv6 — checado depois da resolução, para um nome que rebinde não
  escapar.

Isto exige um pequeno refactor: a guarda, hoje no pacote `resthttp`, sobe para
um pacote que os dois adaptadores importam (p.ex. `internal/egress`), em vez de
ser duplicada. O `remotemcp` monta o `*http.Client` do transporte de cliente
com esse `DialContext` e esse `checkRedirect`.

### 8. Tools dinâmicas: re-quarentena, pelo mesmo ticker

Um MCP remoto pode mudar as tools que anuncia, e pode mandar
`notifications/tools/list_changed`. A decisão é **re-quarentena, não freeze**:
uma tool cujo fingerprint muda vira `changed`, fica invisível e não-chamável
até ser reaprovada — a semântica de quarentena que já existe.

Isto não acrescenta mecanismo novo: o `Gateway.Refresh` (`0013`) já reobserva
ao vivo todos os upstreams conectados a cada tick e entrega cada lista à
quarentena, e o `remotemcp.ListTools` delega à sessão viva como o `stdio`.
Então a re-quarentena de `remote` acontece pelo mesmo ticker, sem código novo.

A notificação `list_changed` continua sendo o que o `0013` já diz que é: uma
otimização de latência, opcional, que um backend comprometido simplesmente não
manda — se um dia for ligada (o cliente do SDK aceita o handler), ela dispara
um `Refresh` imediato e **nunca** contorna a quarentena. O ticker é o
backstop, como em todos os transportes.

### 9. O que `remote` não isola, e não se afirma que isola

Declarado honestamente, como a lacuna do uid do `stdio` nos `0003`/`0034`:

- **Um backend `remote` é não-isolável por este gateway.** Ele roda no host de
  outra pessoa. Não há uid separado, jail, Capsicum nem container sob nosso
  controle — nós nem spawnamos o processo. É um degrau abaixo do `stdio` (que
  ao menos roda sob o nosso uid) e do `oci` (que roda numa imagem que nós
  fixamos). **A barreira é a confiança do operador no endpoint**, atestada no
  segundo clique de assinatura (`0050` §5) e na aprovação de cada tool.
- **O egresso de saída do backend `remote` é invisível ao `0033`.** O `0033`
  governa o egresso dos backends que **nós** subimos (a política de rede do
  `oci`, a rede do host do `stdio`). O que um MCP remoto faz com a chamada
  depois de recebê-la — para onde ele próprio liga — está inteiramente fora da
  nossa vista. Nós só controlamos o salto gateway→remoto (item 7). Isto **não**
  é coberto e não se afirma coberto.

### 10. O que `remote` reaproveita sem mudança

Por ser um transporte de conexão viva como `stdio`/`oci`, tudo abaixo estende
sem alteração:

- **quarentena por tool** (`0007`/`0013`): o handshake lista as tools, que
  nascem pendentes e são aprovadas por fingerprint;
- **portões do `Dispatch`** (`0035`): kill switch, suspensão, concorrência,
  quota e a trilha-antes-de-encaminhar valem no mesmo ponto único;
- **`scrubResult`** (`0047` §5): mascaramento de credencial devolvida;
- **saúde e redial** (`0024`/`0041`): `ErrUpstreamGone`, estados up/down e
  redial funcionam porque há uma conexão viva a observar.

## Consequências

- Uma equipe pode registrar um MCP nativo de terceiro por URL, com o mesmo
  portão humano (assinatura + aprovação de tool) dos outros transportes, sem
  rodar nada localmente.
- O código ganha um adaptador (`remotemcp`), uma tag de assinatura
  (`v4-remote`), um `case` no dialer, um ramo no `Validate` e um pacote de
  egresso compartilhado — e nada do `Gateway`, da quarentena ou da trilha muda.

## Não cobre, e não se afirma coberto

- **SSE:** reservado em `remote_kind`, construído só quando um backend legado o
  exigir (item 3).
- **OAuth / auth dinâmica:** só bearer/header estático; o cunho de token
  próprio para endpoint OAuth é o MUST adiado (item 6).
- **O egresso de saída do backend remoto** (item 9): fora da vista, gate por
  confiança no endpoint.
- **Isolamento do backend remoto** (item 9): inexistente por natureza.
