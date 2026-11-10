# 0059. O console registra `oci` e `remote` também: o menu "Add" vira uma escolha de três vias; `stdio` continua só na CLI

**Status:** Accepted — 10 nov 2026. Estreita o "Não cobre" de `0050` §2 (que
deixava `stdio` e `oci` fora do console) e anota `0052` (cujo substantivo
"MCP server / API" e cuja página de adicionar hoje significam só REST). Depende
do transporte `remote` (`0058`). Não muda nenhum portão de `0034`, `0048`,
`0049` ou `0050`.

## Contexto

Duas decisões registradas limitavam o que se adiciona pela tela:

- `0050` §2 ("Não cobre") e `0052` §2: **`stdio` e `oci` continuam só na CLI**;
  o console registra só REST (o caminho `http` de `0047`/`0048`).
- `0052` §1: o substantivo "MCP server / API" e o botão "REST API / OpenAPI →
  generates MCP tools" nomeiam só a entrada REST.

O dono aprovou (10 nov 2026) que o console passe a adicionar também (a) um MCP
**remoto/nativo por URL** (`0058`) e (b) um MCP **containerizado `oci`**. O
`stdio` continua só na CLI. A página de adicionar deixa de ter uma via e passa
a ter três.

## Decisão

### 1. O menu "Add" é uma escolha de três vias

`/servers/new` (a sub-página zero-JS de `0052`, nunca um modal) abre com três
opções, cada uma com o seu formulário ciente do transporte:

1. **REST API** — OpenAPI por URL, texto ou upload. Inalterado: é o caminho
   `http` de `0050` §2 / `0052` §2.
2. **Remote MCP server (URL)** — a URL do endpoint, o `remote_kind` (padrão
   streamable, `0058` §3) e, se houver, a referência de auth. Produz uma
   entrada `remote` (`0058`).
3. **Container (oci)** — a imagem fixada por digest, a política de rede
   (`--network=…`) e os nomes das variáveis de ambiente. Produz uma entrada
   `oci` (`0028`).

`stdio` **não** aparece (item 5).

### 2. Contrato: a requisição de registro passa a carregar o transporte

Hoje `POST /v1/upstreams` monta só uma entrada `http` (`registerHTTP` em
`cmd/mcp-gateway`). A requisição ganha `transport` e os campos por transporte
— `image`/`args`/`env_var_names` para `oci`; `url`/`auth`/`remote_kind`/
`env_var_names` para `remote` — na própria operação ou numa irmã.

O serviço `RegisterUpstream` passa a ramificar por transporte, para uma porta
nova `RegisterEntry` que **reaproveita o que já é agnóstico de transporte**:

- `validateEntry` (`cmd/mcp-gateway`), que o `upstream register` da CLI e o
  `POST /v1/upstreams` já compartilham, e que já trata `oci` (digest obrigatório,
  `command`/`url` recusados) e recusará `remote` pela regra de `0058` §4;
- `credentialedStdioRefusal` (`cmd/mcp-gateway/dialer.go`), que é um no-op para
  `oci` e `remote` e só morde `stdio` com credencial.

Só a via REST mantém a etapa extra de ingestão (`ingestHTTP`: OpenAPI →
conjunto de operações). `oci` e `remote` não ingerem nada: montam a entrada,
passam por `validateEntry` + `credentialedStdioRefusal` + `Register`, como a
CLI já faz. O front ganha um formulário ciente do transporte; a lógica de
negócio continua toda na API (`0051`, cliente fino).

### 3. `oci` pela tela exige podman, e sem podman o botão recusa com graça

O `oci` precisa de podman rootless (`0028` §D). A imagem Docker (`0049`) **não
tem podman** — o Gatte lá roda num container só, sem runtime aninhado. Então:

- a opção **Container (oci)** é condicionada a uma feature (`oci_register`),
  presente só quando o host tem podman; na imagem Docker ela **não é oferecida**;
- se mesmo assim for tentada (uma chamada direta à API), a resposta é a recusa
  "sem podman" que já existe, dita por extenso.

**Nunca um botão quebrado:** ou a via não aparece, ou, se chamada, ela explica
por que não roda ali. A tela não oferece um caminho que recusaria (a mesma
regra que `0052` §2 aplicou a `stdio`/`oci`).

### 4. `oci` mantém todo o endurecimento do `0034` e o pino por digest

Registrar `oci` pela tela escreve **a mesma entrada** que a CLI escreveria, e
nada do caminho de execução muda:

- o pino por digest é obrigatório no `Validate` (`registry.validateImage`): uma
  imagem por tag é recusada, no console como na CLI;
- o invólucro do `0028` §A / `0034` (`--cap-drop=all`,
  `--security-opt=no-new-privileges`, `--user=UID:GID`, limites de
  pids/memória/cpu, raiz somente-leitura, `--network` da política assinada) é
  emitido pelo adaptador, sempre, independentemente de quem registrou.

Isto é **inegociável** e não é afrouxado por vir da tela.

### 5. `stdio` continua só na CLI; pela tela seria uma regressão declarada

`stdio` roda sob o uid do próprio gateway, sem isolamento do processo que
guarda as credenciais (AGENTS.md §2; `0003`; `0034`). Oferecê-lo pela tela,
sobretudo com credencial, é a regressão que o `0034` cercou com
`allow_credentialed_stdio`. Então:

- `stdio` **não** entra no menu "Add" (item 1);
- se um dia entrar, é atrás de `allow_credentialed_stdio` **e** de um portão de
  console separado, e é uma **regressão declarada**, nunca um default. O
  default é **NÃO**, e este ADR não o constrói.

### 6. Os portões humanos são os mesmos para todo transporte

- **Assinar é um segundo clique atestante** (`0050` §5): registrar — REST,
  `remote` ou `oci` — **não** assina. A página de resultado mostra o que será
  atestado (para `oci`: o digest da imagem, a política de rede, os nomes de
  variável; para `remote`: a URL, o descritor de auth e o `remote_kind`; para
  REST: o que `0052` §3 já lista), e só ali há o botão de atestar (`0060`).
- **As tools nascem pendentes** e são invisíveis até aprovação por fingerprint
  (`0032`/`0036`); tool sensível exige `clear` e um papel `non_read` que a
  nomeie (`0048` §5). O console não contorna nenhum desses portões, em nenhum
  transporte.
- **Desregistrar** pede o nome digitado, porque apaga as aprovações junto
  (`0050` §2).

## Consequências

- O operador adiciona, pela mesma tela, uma API REST, um MCP remoto por URL ou
  um MCP em container, e entende por rótulo o que cada um é.
- O contrato ganha `transport` e os campos por transporte; o serviço ganha uma
  porta `RegisterEntry` que reusa `validateEntry` e `credentialedStdioRefusal`;
  o front ganha um formulário ciente do transporte.
- Nada do endurecimento do `oci` (`0034`), da assinatura (`0028`/`0058`) ou da
  quarentena muda: é o caminho da CLI, exposto na tela, sob os mesmos portões.

## Não cobre, e não se afirma coberto

- **`stdio` pela tela:** regressão declarada, default NÃO, não construído
  (item 5).
- **`oci` na imagem Docker:** sem podman, a via não é oferecida; se chamada,
  recusa com graça (item 3).
- Os portões e lacunas de cada transporte ficam onde já estão: `0034` (oci),
  `0058` §9 (remote).
