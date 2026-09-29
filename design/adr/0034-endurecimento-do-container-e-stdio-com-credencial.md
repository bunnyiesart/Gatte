# 0034. Endurecimento do container `oci` e `stdio` com credencial

**Status:** Accepted — 28 set 2026.

## Contexto

O invólucro do `0028` §A entregava raiz somente-leitura, sem rede e `--rm`,
mas não tirava capability nenhuma, não fixava uid e não limitava recurso:
o próprio pacote dizia que "nenhum ADR decidiu isso". O uid ficava sendo o
`USER` da imagem, isto é, uma promessa do §B item 2 que o gateway não
conferia, e um backend podia consumir memória, PIDs e CPU do mesmo host
pequeno onde rodam gateway, proxy e IdP.

Do lado `stdio`, um backend roda com o uid do gateway: um `open()` na chave
age é o cofre inteiro, e não só as credenciais daquela entrada. Nada
impedia registrar assim uma entrada com `-env`. E a lista de variáveis que o
loader lê como código (`LD_*`, `DYLD_*`, `GCONV_PATH`) só era aplicada no
`oci`. O nome é assinado; o valor que o cofre resolve, não. Então um nome
desses faz um valor não assinado virar código ao lado de toda credencial,
com a assinatura ainda válida.

## Decisão

1. **Sem capability e sem ganho de privilégio.** Todo `podman run` leva
   `--cap-drop=all --security-opt=no-new-privileges`, no invólucro fixo, sem
   ajuste. Um backend fala MCP por um pipe e não precisa de capability
   nenhuma.
2. **uid numérico, nunca 0, imposto pela linha de comando.** Todo `run`
   leva `--user=UID:GID`, qualquer que seja o `USER` da imagem. O padrão é
   `65534:65534` e `[oci] user` o troca. Nome é recusado, porque seria
   resolvido pelo `/etc/passwd` da própria imagem, e 0 em qualquer metade
   também. Rejeitado: ler o `USER` da imagem com `podman inspect` no dial e
   recusar root. Isso seria mais uma chamada ao runtime por dial e
   continuaria confiando num metadado da imagem (que pode ser um nome) em
   vez de fixar o fato. Rejeitado também: passar `--user` só quando
   configurado, porque aí uma imagem `USER root` rodaria como root sem
   aviso. O custo, dito: uma imagem cujos arquivos só o próprio `USER` lê
   precisa do uid dela em `[oci] user`, e sem isso falha no primeiro
   `open()`, alto.
3. **Limites de recurso.** `--pids-limit`, `--memory` e `--cpus` sempre, com
   padrões 256, `512m` e `1.0`, ajustáveis em `[oci]`. Zero, negativo,
   ilegível, `cpus` abaixo de 0,01 (piso do podman; abaixo de 0,00001 a
   cota CFS arredonda para 0) e `pids_limit` acima de 4194304 (o
   `PID_MAX_LIMIT` do kernel) são recusados na carga da configuração e de
   novo no dial (`oci.ValidateLimits`). Nenhum valor desliga uma flag.
   `cpus` acima dos núcleos do host não é conferido aqui: o podman o recusa
   no `run`. Os limites valem
   onde o cgroup v2 delega `memory`, `pids` e `cpu` ao usuário do gateway.
   Sem delegação, o `run` falha. Em cgroup v1 rootless, o podman os ignora
   com um aviso no stderr, que o gateway descarta. Conferir no host é do
   operador.
4. **O `Args` da entrada continua restrito.** Ele pode repetir, token a
   token, as flags fixas (agora com as duas do item 1) e `--network`, e nada
   além disso. `--user`, `--pids-limit`, `--memory` e `--cpus` não podem ser
   repetidos, porque uma repetição que divergisse da configuração daria duas
   fontes para um valor. `--cap-add`, `--privileged` e qualquer outro `--security-opt`
   continuam recusados.
5. **Nome que é código, recusado nos dois transportes.** A lista saiu do
   adaptador `oci` para o pacote de porta (`gateway.IsCodeLoadingEnvName`).
   Ela ganhou os ajustes de interpretador (`NODE_OPTIONS`, `PYTHONPATH`,
   `PYTHONSTARTUP`, `PYTHONWARNINGS`, `PERL5OPT`, `PERL5DB`, `RUBYOPT`,
   `BASH_ENV`, o prefixo `BASH_FUNC_`, `JAVA_TOOL_OPTIONS`…) e `PATH` e
   `HOME`, que não são código mas escolhem de onde ele vem (o interpretador
   de um shebang `#!/usr/bin/env`, o site-packages do usuário). É aplicada
   pelo adaptador `stdio` no dial e por `dialTimeRefusal` no `upstream
   register` e no `sign`.
6. **`stdio` com credencial é recusado por padrão.** Uma entrada `stdio` que
   declara `-env` é recusada no `upstream register`, no `sign` e no dial,
   com uma mensagem que aponta `-transport oci`. A saída explícita é
   `[upstreams] allow_credentialed_stdio = true`, para host sem podman (a
   jail FreeBSD) e para os mocks do lab. Todo boot com a chave ligada loga
   um WARN. `examples/base.toml` e o template da jail a ligam. `stdio` sem
   credencial não muda.

## Consequências

- O invólucro de `0028` §A item 1 ganha seis flags; ver a correção lá.
- Uma implantação cujas imagens rodam com um uid próprio põe esse uid em
  `[oci] user`. A implantação de referência leva `[oci] user =
  "10001:10001"`: três das quatro imagens declaram `USER 10001` e uma
  declara `USER 999`, e as quatro respondem ao `initialize` MCP sob
  `10001:10001` com todas as flags deste ADR.
- **Medido em 28/09/2026, na VM de teste** (Linux, podman rootless, cgroup
  v2), com este invólucro: nos quatro containers, `CapEff` e `CapBnd` 0,
  `NoNewPrivs` 1, uid 10001 no container mapeado para um uid subordinado
  no host, `pids.max` 256, `memory.max` 384m, 1 CPU. Os containers rodam
  sob `user@UID.service`, não sob a unit do gateway, então um teto
  systemd para eles vai num drop-in de `user@.service`. Onde o controlador
  não está delegado ao usuário (muitas vezes `cpu`), o crun recusa o
  limite, e o gateway descarta o stderr: a falha aparece só como todo
  upstream `oci` sem dial. Num host novo, antes do corte, rodar como o
  usuário do gateway
  `cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/cgroup.controllers`
  (tem de listar `cpu memory pids`; senão, drop-in `Delegate=cpu memory
  pids` em `user@.service`) e um `podman run` com as flags deste ADR para
  cada imagem.
- Uma configuração que registra `stdio` com `-env` e não tem a chave deixa
  esses upstreams fora no boot (os outros servem), e o log diz por quê.
- Não resolve: perfil seccomp além do padrão do podman, egresso além de
  `--network`, e o runtime continua rodando como o usuário do gateway.

## Compliance

- `internal/gateway/oci`: `TestBuildPlanAssemblesTheWrapperInOrder`,
  `TestTheContainerRunsHardened`, `TestBuildPlanRefusesARootOrSymbolicUser`,
  `TestBuildPlanRefusesALimitThatIsNoLimit`,
  `TestEntryArgsCannotLoosenTheHardening`,
  `TestBuildPlanRefusesEnvNamesThatSteerTheContainerRuntime`.
- `internal/gateway/stdio`: `TestDialRefusesAVariableWhoseValueIsCode`.
- `internal/config`: `TestOCISectionRefusesWhatWouldBeNoLimitOrRoot`.
- `cmd/mcp-gateway`: `TestOCIConfigRuleIsTheDialRule`,
  `TestTransportDialerRefusesACredentialedStdioEntry`,
  `TestUpstreamRegister_RefusesACredentialedStdioEntryWithoutTheOptIn`,
  `TestSign_RefusesACredentialedStdioEntryWithoutTheOptIn`,
  `TestBuildServer_TheOptInIsLoud`.
