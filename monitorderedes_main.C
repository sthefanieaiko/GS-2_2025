/* Monitor de Redes Wi-Fi Seguras em Tempo Real com FreeRTOS

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

#include "esp_system.h"
#include "esp_log.h"
#include "esp_task_wdt.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

static const char *TAG = "WiFiMonitor";

/* ---------- CONFIGURAÇÕES ---------- */
#define MONITOR_TASK_PRIO    6  // mais alta - detecta SSID
#define ALERT_TASK_PRIO      4  // trata alertas (fila)
#define SUPERV_TASK_PRIO     2  // supervisão e recuperação

#define MONITOR_STACK        4096
#define ALERT_STACK          4096
#define SUPERV_STACK         4096

#define ALERT_QUEUE_LEN      6
#define MAX_SSID_LEN         32
#define ALERT_SEND_TMO_MS    200

/* Robustez configs */
#define MONITOR_PERIOD_MS    2000
#define MAX_CONSECUTIVE_QUEUE_FAILS 3
#define WATCHDOG_TIMEOUT_MS  5000

/* ---------- TIPOS ---------- */
typedef struct {
    char ssid[MAX_SSID_LEN+1];
    TickType_t timestamp;
} alert_msg_t;

/* ---------- GLOBAIS ---------- */
static QueueHandle_t g_alert_queue = NULL;
static SemaphoreHandle_t g_secure_list_mutex = NULL;
static TaskHandle_t g_task_monitor = NULL;
static TaskHandle_t g_task_alert = NULL;
static TaskHandle_t g_task_superv = NULL;

/* lista de redes seguras (pode ser atualizada em runtime) */
static const char *initial_secure_list[] = {
    "CORP_OFFICE_WIFI",
    "HEINEKEN_GUEST",
    "HOME_SSID_01",
    "OFFICE-PRIVATE",
    "STHEFANIE_AIKO_NET"
};
static size_t secure_list_count = sizeof(initial_secure_list)/sizeof(initial_secure_list[0]);
/* Em runtime manteremos uma cópia mutável */
static char **secure_list = NULL;

/* heartbeats */
static volatile TickType_t monitor_heartbeat = 0;
static volatile TickType_t alert_heartbeat = 0;

/* ---------- FUNÇÕES AUXILIARES ---------- */

/* retorna true se ssid estiver na lista segura (usa mutex) */
static bool is_ssid_secure(const char *ssid)
{
    bool found = false;
    if (g_secure_list_mutex == NULL) return false;
    if (xSemaphoreTake(g_secure_list_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        for (size_t i = 0; i < secure_list_count; ++i) {
            if (secure_list[i] && strcmp(secure_list[i], ssid) == 0) {
                found = true;
                break;
            }
        }
        xSemaphoreGive(g_secure_list_mutex);
    } else {
        // Se não conseguiu pegar mutex, considerar inseguro e deixar o monitor tratar (opção defensiva)
        ESP_LOGW(TAG, "Não foi possível pegar mutex da lista segura -> tratamos como INSEGURA por segurança");
        found = false;
    }
    return found;
}

/* aloca e inicializa a lista mutável a partir do initial_secure_list */
static void secure_list_init()
{
    secure_list = (char **) malloc(sizeof(char*) * secure_list_count);
    if (!secure_list) {
        ESP_LOGE(TAG, "Falha alocar memória para secure_list. Reiniciando.");
        esp_restart();
    }
    for (size_t i = 0; i < secure_list_count; ++i) {
        secure_list[i] = strdup(initial_secure_list[i]);
        if (!secure_list[i]) {
            ESP_LOGE(TAG, "Falha strdup. Reiniciando.");
            esp_restart();
        }
    }
}

/* limpa a lista (free) */
static void secure_list_free()
{
    if (!secure_list) return;
    for (size_t i = 0; i < secure_list_count; ++i) {
        if (secure_list[i]) {
            free(secure_list[i]);
            secure_list[i] = NULL;
        }
    }
    free(secure_list);
    secure_list = NULL;
}

/* ---------- TAREFAS ---------- */

/* Tarefa Monitor: verifica SSID periodicamente e gera alertas para redes não seguras */
void task_monitor(void *pv)
{
    ESP_LOGI(TAG, "task_monitor START");
    esp_task_wdt_add(NULL);

    int queue_fail_counter = 0;

    for (;;) {
        /* atualiza heartbeat */
        monitor_heartbeat = xTaskGetTickCount();

        /* obtém SSID AP ao qual está associado (assumindo STA) */
        wifi_ap_record_t ap_info;
        esp_err_t err = esp_wifi_sta_get_ap_info(&ap_info);
        if (err == ESP_OK) {
            char current_ssid[MAX_SSID_LEN+1] = {0};
            memcpy(current_ssid, ap_info.ssid, strnlen((char*)ap_info.ssid, MAX_SSID_LEN));
            current_ssid[MAX_SSID_LEN] = 0;

            ESP_LOGI(TAG, "Conectado à SSID: %s", current_ssid);

            if (!is_ssid_secure(current_ssid)) {
                /* rede não autorizada: gerar alerta (alocando dinamicamente) */
                alert_msg_t *msg = (alert_msg_t *) malloc(sizeof(alert_msg_t));
                if (msg == NULL) {
                    ESP_LOGE(TAG, "[ALERTA] Falha ao alocar memória para mensagem de alerta");
                    // estratégia de recuperação leve: resetar WDT e tentar mais tarde
                    esp_task_wdt_reset();
                } else {
                    strncpy(msg->ssid, current_ssid, MAX_SSID_LEN);
                    msg->ssid[MAX_SSID_LEN] = '\0';
                    msg->timestamp = xTaskGetTickCount();

                    if (xQueueSend(g_alert_queue, &msg, pdMS_TO_TICKS(ALERT_SEND_TMO_MS)) != pdTRUE) {
                        ESP_LOGW(TAG, "[ALERTA] Fila de alertas cheia, não enviou (ssid=%s)", msg->ssid);
                        free(msg);
                        queue_fail_counter++;
                        if (queue_fail_counter >= MAX_CONSECUTIVE_QUEUE_FAILS) {
                            ESP_LOGE(TAG, "Falha persistente na fila de alertas -> resetando fila e notificando supervisor");
                            xQueueReset(g_alert_queue);
                            queue_fail_counter = 0;
                        }
                    } else {
                        ESP_LOGI(TAG, "[ALERTA] Enviado alerta para SSID não autorizada: %s", msg->ssid);
                        queue_fail_counter = 0;
                    }
                }
            } else {
                // SSID segura -> nada a fazer
            }
        } else {
            // Não está conectado; tratativa defensiva:
            ESP_LOGW(TAG, "Não conectado a AP (esp_wifi_sta_get_ap_info returned 0x%x). Verificar estado Wi-Fi.", err);
            // opcionalmente: enviar alerta sobre desconexão se necessário
        }

        /* monitora heap e stack watermark (robustez) */
        size_t free_heap = xPortGetFreeHeapSize();
        if (free_heap < 20 * 1024) {
            ESP_LOGW(TAG, "Heap baixo: %u bytes", (unsigned int) free_heap);
        }

        esp_task_wdt_reset();
        vTaskDelay(pdMS_TO_TICKS(MONITOR_PERIOD_MS));
    }
}

/* Tarefa Alert Handler: consome a fila de alertas e faz log / ações (ex.: buzina, LED, enviar para servidor) */
void task_alert_handler(void *pv)
{
    ESP_LOGI(TAG, "task_alert_handler START");
    esp_task_wdt_add(NULL);

    for (;;) {
        alert_msg_t *msg = NULL;
        if (xQueueReceive(g_alert_queue, &msg, pdMS_TO_TICKS(1000)) == pdTRUE) {
            alert_heartbeat = xTaskGetTickCount();

            if (msg) {
                /* Log simples quando alerta for gerado (obrigatório) */
                printf("[ALERTA] Rede NÃO AUTORIZADA detectada! SSID=\"%s\" ticks=%u\n",
                       msg->ssid, (unsigned int) msg->timestamp);

                /* Aqui você pode: piscar LED, acionar buzina, enviar notificação via MQTT/HTTP, etc.
                 * Exemplo simples: marcar um flag, ou salvar em NVS/log local.
                 */

                /* libera memória da mensagem */
                free(msg);
            }
        } else {
            /* Timeout na fila (nenhum alerta neste periodo) - comportamento normal */
            // opcional: printf("[ALERT_HANDLER] nenhum alerta recebido no periodo\n");
        }

        esp_task_wdt_reset();
    }
}

/* Tarefa Supervisora: monitora heartbeats e re-cria tarefas em caso de falha; checa uso de heap mínimo e reinicia se necessário */
void task_supervisor(void *pv)
{
    ESP_LOGI(TAG, "task_supervisor START");
    esp_task_wdt_add(NULL);

    const TickType_t check_period = pdMS_TO_TICKS(3000);
    int alert_recreate_count = 0;

    for (;;) {
        vTaskDelay(check_period);

        TickType_t now = xTaskGetTickCount();

        /* Verifica heartbeats: monitor e alert_handler */
        if (now - monitor_heartbeat > pdMS_TO_TICKS(2 * MONITOR_PERIOD_MS)) {
            ESP_LOGW(TAG, "Monitor inativo. Tentando recriar a tarefa monitor...");
            if (g_task_monitor) {
                vTaskDelete(g_task_monitor);
                g_task_monitor = NULL;
            }
            xTaskCreatePinnedToCore(task_monitor, "task_monitor", MONITOR_STACK, NULL, MONITOR_TASK_PRIO, &g_task_monitor, 1);
            monitor_heartbeat = xTaskGetTickCount();
        }

        if (now - alert_heartbeat > pdMS_TO_TICKS(10 * 1000)) {
            ESP_LOGW(TAG, "Alert handler inativo por >10s. Recriando...");
            if (g_task_alert) {
                vTaskDelete(g_task_alert);
                g_task_alert = NULL;
            }
            xTaskCreatePinnedToCore(task_alert_handler, "task_alert", ALERT_STACK, NULL, ALERT_TASK_PRIO, &g_task_alert, 1);
            alert_recreate_count++;
            alert_heartbeat = xTaskGetTickCount();
        }

        /* Verifica heap crítico */
        size_t free_heap = xPortGetFreeHeapSize();
        size_t min_heap  = xPortGetMinimumEverFreeHeapSize();
        ESP_LOGI(TAG, "Supervisor: heap livre=%u bytes (mín histor=%u)", (unsigned int)free_heap, (unsigned int)min_heap);

        if (free_heap < 12 * 1024) {
            ESP_LOGE(TAG, "Heap crítico detectado (%u bytes). Reiniciando sistema para recuperar estado.", (unsigned int)free_heap);
            vTaskDelay(pdMS_TO_TICKS(200));
            esp_restart();
        }

        /* Se tivemos recriações frequentes, decidir reiniciar para limpar estado */
        if (alert_recreate_count >= 3) {
            ESP_LOGE(TAG, "Recriação frequente da task_alert detectada. Reiniciando sistema.");
            vTaskDelay(pdMS_TO_TICKS(200));
            esp_restart();
        }

        esp_task_wdt_reset();
    }
}

/* ---------- INICIALIZAÇÃO ---------- */
void app_main(void)
{
    /* Init NVS (requisito para Wi-Fi normalmente) */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    ESP_LOGI(TAG, "Iniciando Monitor de Redes Seguras (FreeRTOS) ...");

    /* Inicializa watchdog de tarefas (robustez) */
    esp_task_wdt_config_t wdt_config = {
        .timeout_ms = WATCHDOG_TIMEOUT_MS,
        .idle_core_mask = (1 << 0) | (1 << 1),
        .trigger_panic = false
    };
    esp_task_wdt_init(&wdt_config);

    /* Cria fila de alertas */
    g_alert_queue = xQueueCreate(ALERT_QUEUE_LEN, sizeof(alert_msg_t *));
    if (!g_alert_queue) {
        ESP_LOGE(TAG, "Falha ao criar fila de alertas. Reiniciando.");
        esp_restart();
    }

    /* Cria mutex para lista segura */
    g_secure_list_mutex = xSemaphoreCreateMutex();
    if (!g_secure_list_mutex) {
        ESP_LOGE(TAG, "Falha ao criar mutex. Reiniciando.");
        esp_restart();
    }

    /* Inicializa cópia mutável da lista segura */
    secure_list_init();

    /* Inicializa indicador de heartbeats */
    monitor_heartbeat = xTaskGetTickCount();
    alert_heartbeat   = xTaskGetTickCount();

    /* Cria tarefas com prioridades diferentes */
    xTaskCreatePinnedToCore(task_monitor, "task_monitor", MONITOR_STACK, NULL, MONITOR_TASK_PRIO, &g_task_monitor, 1);
    xTaskCreatePinnedToCore(task_alert_handler, "task_alert", ALERT_STACK, NULL, ALERT_TASK_PRIO, &g_task_alert, 1);
    xTaskCreatePinnedToCore(task_supervisor, "task_superv", SUPERV_STACK, NULL, SUPERV_TASK_PRIO, &g_task_superv, 1);

    /* Adiciona as tasks ao WDT (as criadas já chamam esp_task_wdt_add(NULL) internamente) */

    ESP_LOGI(TAG, "Todas as tarefas foram criadas. Sistema em execução.");
}
