# 0033. Egresso dos backends: allowlist de rede no adaptador, destinos no firewall do host

**Status:** Accepted — 28 set 2026.

## Contexto

O `0028` §A item 3 deixou para "ADR próprio" quais valores de `--network`
além de `none` são legítimos, e o adaptador `oci` aceitava qualquer
`--network=VALOR` de um token só; um teste fixava `host` como aceito. Com
`host` o container fica no namespace de rede do gateway: alcança todo
listener em loopback do host (o proxy reverso, o IdP, o que mais rodar ali)
e seu tráfego é indistinguível do tráfego do gateway. `container:NOME` e
`ns:CAMINHO` entram em namespaces que o adaptador não criou, e opções depois
de `:` (`slirp4netns:allow_host_loopback=true`, `pasta:--map-gw`) reabrem o
host de dentro do namespace.

Separadamente, um backend com rede fala com qualquer destino que a rede
dele alcance: API pública, o resto da RFC 1918, `169.254.169.254`. O gateway
não tem como decidir destinos — não faz proxy do tráfego do backend — e um
processo `stdio` usa a rede do host inteira.

## Decisão

### 1. O adaptador decide o namespace, por allowlist

`wrapperNetwork` (`internal/gateway/oci/invocation.go`) aceita só:

- `none`, o padrão quando a entrada não declara rede;
- `slirp4netns` e `pasta`, sem opções;
- o nome de uma rede podman, `^[a-z0-9][a-z0-9_.-]{0,62}$`.

Recusa, com `ErrNetworkNotAllowed`: `host`, `private`, `container:*`,
`ns:*` e qualquer valor com `:` ou `/`. A recusa vale no `Dial` e, pelo
mesmo `dialTimeRefusal`, no `upstream register` e no `sign`
(`TestBuildPlanRefusesANetworkOutsideTheAllowlist`,
`TestRunSign_RefusesAnOCIEntryOnTheHostNetwork`).

Uma entrada já registrada com um valor recusado deixa de ser servida no
próximo boot ou `Reconcile`; o conserto é reescrevê-la com um valor da lista
e reassinar.

### 2. O firewall do host decide os destinos

Conter o egresso é trabalho do firewall do host, não do gateway. Sob podman
rootless, `slirp4netns`, `pasta` e as redes nomeadas saem pelo host em
processos do usuário do serviço (`mcpgw`), e um filho `stdio` é esse mesmo
usuário. Uma regra de saída por uid (`meta skuid mcpgw` no nftables, ou o
equivalente do pf) cobre os dois transportes com uma lista só:

- permite a união dos destinos `host:porta` que os backends com rede
  precisam, mais os do próprio gateway (IdP, entrada GELF, resolvedor DNS);
- descarta o resto da RFC 1918, `169.254.0.0/16` e, onde couber, loopback.

Como o uid é compartilhado, a lista é a união: um backend alcança o destino
de outro. Precisão por entrada (`allow_hosts` assinado com proxy
CONNECT/SNI no binário) é um passo posterior e não está decidido aqui.

### 3. Como a implantação deriva a lista

Um campo de egresso novo na entrada mudaria a forma canônica assinada e
exigiria reassinar tudo; não foi feito. A declaração assinada que já existe
é o `--network` no `Args`. `mcp-gateway upstream list -json` a expõe por
entrada em `network`, calculado pela mesma regra que monta o argv
(`TestResolveNetworkIsThePolicyTheDialRuns`,
`TestRunUpstreamList_JSONStatesEachEntrysNetwork`):

| `network` | significado para o firewall |
|---|---|
| `none` | nada a liberar |
| `slirp4netns`, `pasta`, nome de rede | precisa dos destinos dessa entrada |
| `host` | entrada `stdio`: precisa dos destinos dessa entrada |
| `""` com `network_error` | o gateway recusa a entrada; nada a liberar |

Os destinos em si não estão no registro — ficam nos valores do cofre
(URLs de API). O repositório de implantação mantém, revisado por diff, um
mapa `nome da entrada → host:porta`, e um verificador que falha quando uma
entrada com `signature = valid` e `network ≠ none` não tem destinos no
mapa, ou quando o mapa lista uma entrada que não tem rede.

## Consequências

- `host` e os modos que entram em namespace alheio deixam de ser uma edição
  assinada de distância; alargar a rede continua sendo diff assinado.
- Sem a regra do host, um backend com rede alcança tudo o que a rede dele
  alcança. O README diz isso em "Security model".
- A allowlist governa só o que a entrada escreve. O host ainda pode abrir
  o próprio loopback a um modo aceito: `network_cmd_options` (slirp4netns)
  e `pasta_options` no `containers.conf`, o padrão do `pasta` da versão
  instalada, e a rootless-netns por trás de uma rede nomeada
  (`host.containers.internal`). Isso é configuração do host, revisada com
  ela, e a implantação verifica com uma sonda em vez de confiar no padrão:
  para cada modo em uso — `slirp4netns`, `pasta` e cada rede nomeada que
  aparece em `network` no `list -json` — conectar de dentro do container a
  uma porta em loopback do host tem de falhar.
- Uma recusa cita o valor só até o primeiro `:`, `/` ou `=`
  (`TestNetworkRefusalQuotesOnlyTheRejectedHead`): opções e caminhos não
  vão para o stderr, o log nem o `network_error`.
