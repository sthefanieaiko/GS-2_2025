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

<img width="1252" height="923" alt="image" src="https://github.com/user-attachments/assets/3d688282-0004-4da3-be90-f253819668a8" />
<img width="1251" height="916" alt="image" src="https://github.com/user-attachments/assets/8f3eb937-5150-4b77-8608-46e4450c26e3" />
<img width="1237" height="404" alt="image" src="https://github.com/user-attachments/assets/6ae0ca00-0704-4270-ad9b-a2f66b6ad970" />
<img width="1248" height="918" alt="image" src="https://github.com/user-attachments/assets/2dae47bc-0b98-4d8a-897f-685b7e68d831" />
<img width="1255" height="886" alt="image" src="https://github.com/user-attachments/assets/55308cfb-7284-452d-a238-c033a5bb5ea6" />
<img width="1075" height="564" alt="image" src="https://github.com/user-attachments/assets/3fc403bb-7bb4-4af7-b1b0-180d8d258523" />




