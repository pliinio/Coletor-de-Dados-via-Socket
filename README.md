# Coletor de dados socket

Este projeto é uma ferramenta simples desenvolvida em **Python**, utilizando a biblioteca **socket**, com o objetivo de realizar a **coleta de dados básicos de serviços expostos em uma rede TCP**.

A aplicação realiza conexões diretas às portas especificadas, identificando serviços ativos e capturando banners quando disponíveis, simulando uma etapa comum de **Footprinting em Pentest**.

---

## O que o projeto faz

- Verifica portas TCP abertas em um alvo
- Identifica serviços comuns associados às portas
- Realiza banner grabbing
- Detecta exposição de serviços sensíveis
- Gera automaticamente um **relatório técnico em formato `.txt`**
- Gera um **hash SHA256** do relatório para garantir integridade

---

## Saída gerada

Ao final da execução, o script produz:

### 1. Relatório em TXT
Um arquivo de relatório contendo:
- Alvo analisado
- Data e horário do scan
- Lista de portas abertas
- Serviço identificado
- Banner capturado (quando disponível)
- Alerta para serviços sensíveis expostos
- Resumo do scan

### 2. Hash de integridade
Um hash SHA256 do relatório gerado, permitindo validar a integridade do arquivo.

---

Este projeto tem como foco o **entendimento em baixo nível de como funciona a enumeração de serviços em redes**, sem depender de ferramentas prontas, adicionando independência ao processo de footprinting.
