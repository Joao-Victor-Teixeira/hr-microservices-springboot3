# hr-microservices-springboot3

![Java 21](https://img.shields.io/badge/java-21-blue?logo=openjdk)
![Spring Boot 3](https://img.shields.io/badge/spring--boot-3.5.x-brightgreen?logo=springboot)
![Spring Cloud](https://img.shields.io/badge/spring--cloud-2024.x-green?logo=spring)
![License](https://img.shields.io/badge/license-MIT-grey)

Sistema distribuído de Recursos Humanos (RH) construído com Arquitetura de Microsserviços, focado na modernização e migração total de stack legado para o ecossistema Cloud Native atual.

> **⚠️ Nota de Engenharia:** Este projeto **não** é uma reprodução passiva de tutorial. Trata-se de um desafio técnico de **migração e refatoração completa** do projeto original do curso de Microsserviços Java. O objetivo central foi adaptar uma arquitetura baseada em Spring Boot 2 e componentes Netflix OSS depreciados (Zuul, Ribbon, Hystrix) para **Java 21**, **Spring Boot 3** e componentes nativos do **Spring Cloud**, sem uso de código legado.

---

## 🎯 Sobre o Projeto

O sistema simula um ecossistema de RH onde microsserviços independentes colaboram para processar pagamentos e gerir trabalhadores. O foco principal deste repositório é demonstrar proficiência em **resolver problemas de compatibilidade (Breaking Changes)** e implementar padrões de projeto modernos.

A arquitetura resolve desafios clássicos de sistemas distribuídos:
* **Service Discovery:** Como os serviços se encontram dinamicamente.
* **Load Balancing:** Distribuição de carga inteligente (Client-side).
* **Tolerância a Falhas:** Circuit Breakers para evitar falhas em cascata.
* **Gateway & Roteamento:** Ponto único de entrada e segurança.

---

## 🛠 Tecnologias e Estratégia de Migração

O grande diferencial deste projeto é a atualização da stack tecnológica. Abaixo, a comparação entre o modelo original (Curso) e a implementação realizada neste repositório:

| Componente | Abordagem Original (Legado) | **Abordagem Hardcore (Atual)** |
| :--- | :--- | :--- |
| **Linguagem** | Java 11 | **Java 21 (LTS)** |
| **Framework** | Spring Boot 2.3.x | **Spring Boot 3.5.x** |
| **Core** | `javax.*` | **`jakarta.*`** |
| **API Gateway** | Netflix Zuul 1 (Bloqueante) | **Spring Cloud Gateway (Reativo/Netty)** |
| **Load Balancer** | Netflix Ribbon | **Spring Cloud LoadBalancer** |
| **Resiliência** | Netflix Hystrix | **Resilience4j (Circuit Breaker)** |
| **Segurança** | Oauth2 / WebSecurityConfigurerAdapter | **Spring Security 6 / SecurityFilterChain** |

**Outras tecnologias aplicadas:**
* **Persistência:** Spring Data JPA / Hibernate
* **Banco de Dados:** H2 Database (In-memory para testes rápidos)
* **Comunicação:** OpenFeign (Declarative REST Client)
* **Configuração:** Spring Cloud Config Server
* **Build:** Maven

---

## 🏗 Arquitetura dos Microsserviços

O sistema é composto pelos seguintes módulos (baseado no padrão de referência):

1.  **hr-eureka-server:** Servidor de descoberta onde todos os serviços se registram.
2.  **hr-gateway:** O guardião do sistema. Roteia as requisições externas para os serviços internos e gerencia a autorização.
3.  **hr-worker:** Microsserviço de domínio. Responsável pelo cadastro e consulta de trabalhadores e seus salários.
    * *Status:* ✅ Implementado com Java 21 records/lambdas e tratamento de exceções.
4.  **hr-payroll:** Microsserviço de processamento. Calcula a folha de pagamento consumindo o `hr-worker` via Feign Client.
5.  **hr-user:** Microsserviço de autenticação e usuários.
6.  **hr-oauth:** Servidor de autorização (Auth Server) emitindo tokens JWT.

---

## 🚀 Como Executar

Pré-requisitos: **Java 21** e **Maven**.

1.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/Joao-Victor-Teixeira/hr-microservices-springboot3.git](https://github.com/Joao-Victor-Teixeira/hr-microservices-springboot3.git)
    ```

2.  **Ordem de Inicialização (Importante):**
    Como é um sistema distribuído, respeite a ordem para evitar erros de conexão:
    1.  `hr-eureka-server` (Porta 8761) - *Aguarde iniciar*
    2.  `hr-worker` (Porta 8001)
    3.  `hr-payroll` (Porta 8101)
     
3.  **Teste Rápido (Worker):**
    ```bash
    # Listar trabalhadores
    GET http://localhost:8001/workers
    ```

---

## ✨ Funcionalidades e Conceitos Aplicados

* **API RESTful:** Implementação limpa seguindo as melhores práticas do protocolo HTTP (Verbos corretos, Status Codes 200/404/500 geridos).
* **Injeção de Dependência:** Uso de construtores e anotações do Spring para gestão de beans.
* **Tratamento de Erros:** Uso de `Optional` e Lambdas para evitar *NullPointerException* e garantir respostas JSON consistentes.
* **Comunicação Síncrona:** Uso do **OpenFeign** para comunicação entre microsserviços (Payroll -> Worker) de forma transparente.
