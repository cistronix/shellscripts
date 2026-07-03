# overview-nft.py

Korte beschrijving van `overview-nft.py`.

## Wat dit script doet
- Leest een nftables JSON-ruleset (bestand, stdin of live via `python3-nftables`).
- Zet regels om naar een leesbaar overzicht per table/chain.
- Toont samenvattingen voor:
  - directe accept-poortregels,
  - drop/reject-poortregels,
  - NAT/redirect/masquerade,
  - waarschuwingen voor deels ondersteunde constructies.
- Ondersteunt optioneel een begrensde padanalyse met `--resolve` voor `jump/goto/return`.

## Output
- Formaten: tekst of Markdown (`--format md`).
- Tabellen via `tabulate` indien beschikbaar.

## Opmerking
Dit is statische analyse van de ruleset; het is geen garantie van effectief runtime netwerkgedrag in alle omstandigheden.
