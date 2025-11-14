# GS-2_2025

GS2 - Sistema de Tempo Real

Grupo: 
Sthefanie Aiko Yoshicava - RM 87493 - SALA 5ECS
Ricardo Sampaio Fogaça - RM 86603 - SALA 5ECS
Gabriel Antonio Do Rego - RM 88420 - SALA 5ECS


Monitor de Redes Wi-Fi Seguras em Tempo Real com
FreeRTOS
Objetivo:
Desenvolver um sistema embarcado em FreeRTOS capaz de
monitorar, em tempo real, a rede Wi-Fi à qual o dispositivo está
conectado durante o trabalho, verificando se essa rede está
presente em uma lista de redes seguras.
Caso o dispositivo se conecte a uma rede não autorizada, o
sistema deve emitir um alerta imediato.

O projeto deve usar:
- FreeRTOS no ESP32
- Tarefas (mínimo 3, com prioridades diferentes)
- Fila para comunicação entre tarefas
- Semáforo para proteger o acesso à lista de redes seguras
- Lista de redes deve conter, pelo menos 5 redes
- Pelo menos duas técnicas de robustez (ex.: isolamento,
timeout, WDT, alocação de memória dinâmica, estratégia de
recuperação))
- Registro simples de log (ex.: print) quando um alerta for
gerado
