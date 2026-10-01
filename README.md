# secscan

Motor de **análise estática** extraído do [SecScan](https://github.com/saulofilho/secscan): segredos hardcoded, entropia de Shannon, rotas de API no código, impact score e quality gate para CI.

Gem Ruby e CLI. O mesmo motor existe em Python no pacote `secscan`. O dashboard React continua no repositório original.

## O que esta gem faz

- Aplica as regras do motor (AWS, GCP, GitHub, Stripe, JWT, Slack, chave privada, URI de banco, senha fixa, OpenAI, SendGrid, rotas admin e endpoints)
- Calcula entropia e descarta match abaixo do `minEntropy` da regra
- Ignora `node_modules`, `vendor`, `dist`, lockfiles e padrões extras
- Pondera achado por severidade e criticidade do arquivo
- Impact score de 0 a 100: `100 * (1 - e^(-risco / 55))`
- Exporta tabela, JSON, CSV, SARIF 2.1.0 e Markdown
- Falha o processo com exit code `1` em `--fail-on` ou `--max-risk`

## O que fica de fora

O README do app descreve DAST, fuzzer, WAF, EDR e módulos parecidos. Eles não entram nesta gem. Skill, agente e MCP são o passo seguinte.

Relatórios em arquivo mascaram o segredo. Use `--reveal-secrets` só quando o artefato for restrito. O objeto `Finding` em memória guarda o literal.

## Instalação

```bash
gem install secscan
```

Confirme o nome no RubyGems antes de publicar.

No `Gemfile`:

```ruby
gem "secscan"
```

## CLI

```bash
secscan .
secscan ./src --fail-on critical
secscan . --max-risk 50 --format sarif --output secscan.sarif
secscan . --ignore "tests/*,docs/*" --rules ./rules.json
```

| Flag | Efeito |
|------|--------|
| `--format` | `table` (padrão), `json`, `sarif`, `csv`, `markdown` |
| `--rules` | JSON extra, somado às regras internas |
| `--ignore` | Padrões separados por vírgula |
| `--fail-on` | Exit 1 se houver achado nessa severidade ou acima |
| `--max-risk` | Exit 1 se o impact score passar do teto |
| `--output` | Grava o relatório |
| `--reveal-secrets` | Inclui o valor encontrado |

Exit `0` passa, `1` é quality gate, `2` é caminho ou regras inválidas.

## Uso programático

```ruby
require "secscan"

report = Secscan.scan("./src", ignore: ["tests/*"])
puts report.metrics.security_impact_score
puts report.metrics.impact_level

inline = Secscan.scan_text(%(const key = "AKIAIOSFODNN7EXAMPLE";\n), path: "src/app.js")
puts inline.findings.first.masked_secret
```

Um arquivo de regras é uma lista de objetos com `id`, `name`, `pattern`, `severity`, `category`, `description`, `remediation`, `flags` e `minEntropy`.
