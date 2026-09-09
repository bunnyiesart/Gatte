# 0009. Configuração em TOML, papéis em arquivo e não no banco

**Status:** Accepted

## Contexto

A revisão de pendências de 09 set 2026 encontrou o maior buraco do
projeto: **o gateway não roda.** `cmd/mcp-gateway` continua o esboço da
Fase 1, e não existe mecanismo de configuração nenhum. Tudo que as Fases
2–5 introduziram — issuer e audiência OIDC, nome do claim de grupos,
caminho da identidade age, caminho da chave de assinatura, endereço de
escuta, e **a definição dos papéis** — não tem de onde vir.

Antes de escrever o composition root é preciso decidir duas coisas que
depois ficam caras de mudar: **em que formato** a configuração é escrita, e
**onde vivem os papéis** (a lista de quais ferramentas cada papel pode
chamar).

## Decisão

### 1. TOML, com `github.com/BurntSushi/toml`

Não JSON, apesar de estar na stdlib e custar zero dependência.

O motivo é específico e não é gosto: **JSON não tem comentário.** A
configuração de papéis decide quem pode chamar o quê, e quem a lê às 3h
durante um incidente precisa do *porquê* ao lado da linha — por que este
papel tem esta ferramenta, quem aprovou, quando revisar. Sem comentário,
esse contexto vai para um lugar que ninguém abre junto.

O precedente da organização decide o desempate: `.hardening.toml`, no
próprio repositório, é **densamente comentado**, e os comentários carregam
o significado operacional, não decoração. Quem opera este gateway já lê
TOML comentado como a forma normal de declarar postura de segurança aqui.

Custo medido antes de aceitar, como manda o `0005`:
`github.com/BurntSushi/toml` **não traz dependência transitiva nenhuma** —
é a quinta e única nova dependência direta, ao lado de go-oidc, go-jose,
o SDK de MCP e o driver SQLite.

### 2. Papéis em arquivo versionado, não em tabela

A alternativa séria era guardar papéis no SQLite e administrá-los por
subcomando, igual aos upstreams. Foi rejeitada.

Upstream é **estado operacional**: muda quando um backend entra ou sai,
e o `Operator Console` é o lugar certo para isso. Papel é **política**:
muda quando alguém decide que um cargo passa a poder fazer mais, e essa é
uma decisão que merece revisão por outra pessoa antes de valer.

Em arquivo versionado, mudar um papel é um commit assinado com Pull
Request — que é exatamente o processo que o padrão de hardening já
impõe a este repositório, e o mesmo raciocínio que fez `sops+age` ganhar
no `0003` por o arquivo cifrado ser "git-safe e revisável". Em tabela,
alargar um papel é um comando que não deixa rastro revisável e cujo
histórico morre com o banco.

Consequência aceita: recarregar papéis exige reiniciar o processo (ou um
reload explícito). Para uma equipe de ~7 pessoas cujos papéis mudam
raramente, isso é preço baixo por revisibilidade.

### 3. Segredo nenhum no arquivo de configuração

O arquivo carrega **caminhos** e **identificadores**, jamais valores:
caminho da identidade age, caminho da chave de assinatura, issuer,
audiência. Os segredos continuam onde o `0003`, o `0005` e o `0006` já os
puseram — no arquivo sops cifrado e nos arquivos de chave com permissão
restrita.

Isso é o que permite versionar o arquivo de configuração sem cerimônia, e
o que faz o hook de pre-commit do template não ter nada para barrar nele.

## Consequências

**Impactos positivos:** uma mudança de política é um diff revisável;
comentários ficam ao lado do que explicam; o formato é o mesmo que a
organização já usa para postura de segurança; uma dependência a mais, sem
cauda transitiva.

**Impactos negativos aceitos:** uma dependência a mais, ainda assim; e
papéis não são editáveis em tempo de execução, então alargar um papel
durante um incidente exige um deploy, não um comando. Deliberado — é a
mesma troca que a quarentena já faz ao ser "mais lenta por design".

**Trade-offs assumidos:** trocamos edição rápida por revisibilidade, no
único eixo do sistema que decide quem pode chamar o quê.

## Compliance

- [x] Automatizável? Sim, parcialmente.
- Mecanismo: `internal/config` valida na carga e recusa arquivo malformado
  na inicialização, não na primeira requisição — mesmo raciocínio de
  `access.NewPolicy`, que recusa um mapeamento para papel inexistente na
  construção. Um teste garante que nenhum campo do arquivo aceita valor de
  segredo (apenas caminho ou identificador).
- O que **não** é automatizável: a permissão dos arquivos apontados. Fica
  em `deploy/freebsd-jail.md` como pré-requisito conferido à mão.

## Notas

- Autor: Claude, 09 set 2026, início da Fase 6.
- Depende de `0003`/`0005`/`0006` (onde os segredos vivem) e desbloqueia
  ISSUE-17 (composition root) e ISSUE-18 (ligar o Definition Signer).
