# 0038. Contas do IdP pelo console

**Status:** Accepted — 29 set 2026.

## Contexto

Quem chama o gateway é decidido fora dele: o IdP guarda as pessoas e seus
grupos, e `config.toml` mapeia grupos para papéis (`[group_to_role]`,
`[[role]]`). Para dar acesso a alguém, o operador editava à mão o arquivo de
usuários do Authelia, com um hash argon2 gerado à parte, e o console web
(`0036`) não mostrava nem os papéis nem quem já usou o gateway.

Editar contas é a operação mais sensível que o console poderia ter. Quem
escreve o arquivo de usuários do IdP cria uma conta e lhe dá qualquer grupo,
logo qualquer papel. Se o usuário de serviço pudesse escrever esse arquivo,
quem executa código como o gateway se daria acesso a todas as tools.

## Decisão

### 1. Página People, para todos

`/people` mostra os papéis com seus grupos e tools, e quem a trilha já viu
(sujeito, última chamada, número de chamadas), com um botão Block que é o
`access block` de sempre (`0031`). Só leitura.

### 2. Edição de contas só num console root

*Revisto por `0040`:* a regra passa a ser do socket de contas
(`mcp-gateway admin -accounts`, só root). As operações abaixo são as do
serviço de gestão (`internal/admin`), que o console chama por esse socket.
`-manage-users` agora quer dizer "abrir também o socket de contas": com
`sudo`, ou sem ele para um membro de `[admin] account_group` quando o
socket é delegado. O console recusa um socket de contas cujo servidor não
seja root, e o `keepDBOwner` deixou de existir: nenhum processo do console
abre o banco. O que está abaixo sobre o processo do `ui` ser root descreve
a primeira versão.

`sudo mcp-gateway ui -manage-users` liga a edição: adicionar uma pessoa,
trocar seus grupos, desativar, reativar e gerar uma senha nova. O comando
recusa se o processo não for root, e o console normal, que roda como o
usuário de serviço, não tem essas rotas (404). É a mesma regra do `sign`
(`0010`): o que dá confiança não pode estar ao alcance do usuário de
serviço.

- O arquivo vem de `[idp] users_file`, no `config.toml` que é do root. Ligar
  o modo é uma mudança revisada. Só o backend de arquivo do Authelia é
  suportado.
- Só se atribuem grupos que existem em `[group_to_role]`. O console dá
  acesso pelo mapeamento, nunca por fora dele.
- A senha inicial e a de reset são aleatórias (20 caracteres, cerca de 117
  bits), mostradas uma vez na página de resultado e gravadas só como hash
  argon2id com os parâmetros padrão do Authelia (`m=65536,t=3,p=4`). Não vão
  para log nem para a trilha.
- O arquivo é editado pela árvore YAML: comentários, ordem e as outras
  contas voltam como estavam. A escrita é um arquivo temporário no mesmo
  diretório, com o modo e o dono do original, sincronizado e renomeado.
- Cada mudança grava uma linha de operador na trilha: `(account add)`,
  `(account groups)`, `(account disable)`, `(account enable)`,
  `(account reset password)`, com o username e os grupos na razão e `[ui]`.
  O arquivo é escrito primeiro e a trilha depois, como no `access block`.
- Um processo root que abre o banco pode criar `-wal` e `-shm` com dono
  root, e o serviço perderia a escrita no próprio banco. Depois de cada ação,
  o console devolve esses arquivos ao dono do banco.

## Consequências

- Adicionar alguém é um formulário: nome, username, email e grupos, e a
  senha de uso único para entregar.
- O Authelia só vê a mudança quando relê o arquivo: `watch: true` na
  configuração dele, ou um restart. A página diz isso.
- Desativar impede login novo, mas não derruba um token já emitido; para
  isso existe o Block.
- Não resolve: LDAP e outros backends; remover uma conta (fica no arquivo,
  à mão); quem troca a própria senha (é o fluxo de reset do IdP).

## Testes

`internal/idp` (formato do hash argon2id, senha gerada, validação da conta);
`internal/idp/autheliafile` (leitura, inclusão sem perder comentários nem as
outras contas, edição só da conta pedida, modo do arquivo e nenhum temporário
sobrando); `cmd/mcp-gateway/ui_people_test.go` (página People; edição
inexistente sem `-manage-users`; incluir grava o arquivo, mostra a senha uma
vez e audita sem ela; grupo sem papel recusado; grupos, desativar, reativar e
reset; `-manage-users` recusado fora do root). *Revisto por `0040`:* o último
é agora `TestUI_ManageUsersRefusesAnAccountsSocketNotServedByRoot`.
