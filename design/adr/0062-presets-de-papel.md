# 0062. Presets de papel: "New role from preset", modelos no arquivo de papéis

**Status:** Accepted — 11 nov 2026. Anota `0050` §3 (o arquivo de papéis) e
`0054` (edição cirúrgica do arquivo pelos fronts). Não muda a política de
acesso, a quarentena nem `0048`.

## Contexto

O console e o TUI editam papéis que já existem (dar e tirar tools, marcar
`non_read`), mas não criam um papel. Criar um papel novo hoje é editar o
arquivo à mão. O time monta quase sempre os mesmos conjuntos de tools
("analista blue team", "analista red team"), e o dono pediu um "New role
from preset".

## Decisão

1. **Preset é um modelo, não um papel.** `[[preset]]` com `name` e `tools`
   (nomes `BACKEND.TOOL`) mora no arquivo que guarda os papéis — com
   `roles_file`, só nele. A carga valida (nome único e sem espaço nas
   pontas, lista não vazia, nomes com namespace, sem curinga, sem repetição),
   mas o `serve` não lê preset: ele não concede nada, e mudar um preset não
   pede `reload` nem restart (fica fora do diff "NOT applied until a
   restart").
2. **Criar a partir do preset escreve grants.** `frontkit.NewRoleFromPreset`
   acrescenta um `[[role]]` novo depois do último papel, com as tools do
   preset em `[role.grants]`, e mapeia os grupos pedidos em
   `[group_to_role]`. Nada mais do arquivo muda (`0054`). O texto passa pelo
   `PUT /v1/roles`, que valida como a carga.
3. **Preset nunca torna um papel capaz de agir.** O papel criado não recebe
   `non_read`, e um grant nunca alcança tool sensível (`0048`). Então a tool
   que o front classifica como sensível é pulada — em vez de virar um grant
   que não alcança nada — e devolvida para a tela listar. Concedê-la continua
   sendo dois atos explícitos: marcar `non_read` e nomear a tool em `tools`.
4. **Papel vazio também.** `frontkit.NewRole` cria o papel sem tools, com os
   grupos, para quem não quer partir de um preset.

## Consequências

- Um preset errado não abre acesso: na pior hipótese, cria um papel com
  grants que o operador ainda revisa e aplica com `reload`.
- A lista de presets é texto revisável no mesmo diff dos papéis (`0009`).
- Os fronts precisam da classificação das tools (já vêm do catálogo da API)
  para dizer quais foram puladas.
