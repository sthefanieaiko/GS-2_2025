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
#include "esp_event.h"
#include "nvs_flash.h"
#include "esp_netif.h"

static const char *TAG = "WiFiMonitor";

/* ---------- CONFIGURAÇÕES ---------- */
#define MONITOR_TASK_PRIO    6
#define ALERT_TASK_PRIO      4
#define SUPERV_TASK_PRIO     2

#define MONITOR_STACK        4096
#define ALERT_STACK          4096
#define SUPERV_STACK         4096

#define ALERT_QUEUE_LEN      6
#define MAX_SSID_LEN         32
#define ALERT_SEND_TMO_MS    200

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

static const char *initial_secure_list[] = {
    "CORP_OFFICE_WIFI",
    "RICARDO_GUEST",
    "HOME_SSID_01",
    "OFFICE-PRIVATE",
    "STHEFANIE_AIKO_NET"
};

static size_t secure_list_count = sizeof(initial_secure_list)/sizeof(initial_secure_list[0]);
static char **secure_list = NULL;

static volatile TickType_t monitor_heartbeat = 0;
static volatile TickType_t alert_heartbeat = 0;

/* ----------------------------------------------- */
/*                 Wi-Fi EVENTS                    */
/* ----------------------------------------------- */
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "Wi-Fi desconectado. Tentando reconectar...");
        esp_wifi_connect();
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ESP_LOGI(TAG, "Conectado com IP obtido.");
    }
}

/* ----------------------------------------------- */
/*            INICIALIZAÇÃO DO WI-FI STA           */
/* ----------------------------------------------- */
static void wifi_init_sta(void)
{
    esp_netif_init();
    esp_event_loop_create_default();

    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = "Sthefanie_casa",
            .password = "sthefanie",
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = {
                .capable = true,
                .required = false,
            },
        },
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Wi-Fi STA inicializado, conectando...");
}

/* ----------------------------------------------- */
/*             LISTA DE REDES SEGURAS             */
/* ----------------------------------------------- */

static bool is_ssid_secure(const char *ssid)
{
    bool found = false;
    if (!g_secure_list_mutex) return false;

    if (xSemaphoreTake(g_secure_list_mutex, pdMS_TO_TICKS(100))) {
        for (size_t i = 0; i < secure_list_count; ++i) {
            if (secure_list[i] && strcmp(secure_list[i], ssid) == 0) {
                found = true;
                break;
            }
        }
        xSemaphoreGive(g_secure_list_mutex);
    }
    return found;
}

static void secure_list_init()
{
    secure_list = malloc(sizeof(char*) * secure_list_count);

    for (size_t i = 0; i < secure_list_count; ++i) {
        secure_list[i] = strdup(initial_secure_list[i]);
    }
}

/* ----------------------------------------------- */
/*                    TAREFAS                      */
/* ----------------------------------------------- */

/* MONITOR — verifica SSID conectada */
void task_monitor(void *pv)
{
    ESP_LOGI(TAG, "task_monitor START");
    esp_task_wdt_add(NULL);

    int queue_fail = 0;

    for (;;) {
        monitor_heartbeat = xTaskGetTickCount();

        wifi_ap_record_t ap_info;
        esp_err_t err = esp_wifi_sta_get_ap_info(&ap_info);

        if (err == ESP_OK) {
            char current_ssid[MAX_SSID_LEN+1] = {0};
            memcpy(current_ssid, ap_info.ssid, strlen((char*)ap_info.ssid));

            ESP_LOGI(TAG, "Conectado à SSID: %s", current_ssid);

            if (!is_ssid_secure(current_ssid)) {
                alert_msg_t *msg = malloc(sizeof(alert_msg_t));
                strcpy(msg->ssid, current_ssid);
                msg->timestamp = xTaskGetTickCount();

                if (xQueueSend(g_alert_queue, &msg, pdMS_TO_TICKS(ALERT_SEND_TMO_MS)) != pdTRUE) {
                    ESP_LOGW(TAG, "Fila cheia — alerta não enviado!");
                    free(msg);
                }
            }
        } else {
            ESP_LOGW(TAG, "Não conectado a AP (0x%x)", err);
        }

        esp_task_wdt_reset();
        vTaskDelay(pdMS_TO_TICKS(MONITOR_PERIOD_MS));
    }
}

/* ALERT HANDLER — consome alertas */
void task_alert_handler(void *pv)
{
    ESP_LOGI(TAG, "task_alert_handler START");
    esp_task_wdt_add(NULL);

    for (;;) {
        alert_msg_t *msg = NULL;

        if (xQueueReceive(g_alert_queue, &msg, pdMS_TO_TICKS(1000))) {
            alert_heartbeat = xTaskGetTickCount();

            printf("\n[ALERTA] Rede NÃO AUTORIZADA detectada!\n");
            printf("SSID: %s\n", msg->ssid);

            free(msg);
        }

        esp_task_wdt_reset();
    }
}

/* SUPERVISOR — reinicia tasks em caso de falha */
void task_supervisor(void *pv)
{
    ESP_LOGI(TAG, "task_supervisor START");
    esp_task_wdt_add(NULL);

    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(3000));

        TickType_t now = xTaskGetTickCount();

        if (now - monitor_heartbeat > pdMS_TO_TICKS(5000)) {
            ESP_LOGW(TAG, "Monitor travado — reiniciando task!");
            vTaskDelete(g_task_monitor);
            xTaskCreatePinnedToCore(task_monitor, "task_monitor", MONITOR_STACK, NULL, MONITOR_TASK_PRIO, &g_task_monitor, 1);
        }

        if (now - alert_heartbeat > pdMS_TO_TICKS(15000)) {
            ESP_LOGW(TAG, "Alert handler travado — reiniciando task!");
            vTaskDelete(g_task_alert);
            xTaskCreatePinnedToCore(task_alert_handler, "task_alert", ALERT_STACK, NULL, ALERT_TASK_PRIO, &g_task_alert, 1);
        }

        esp_task_wdt_reset();
    }
}

/* ----------------------------------------------- */
/*                   APP_MAIN                      */
/* ----------------------------------------------- */

void app_main(void)
{
    nvs_flash_init();

    ESP_LOGI(TAG, "Iniciando sistema...");

    /* Inicializar Wi-Fi STA */
    wifi_init_sta();

    /* Criar fila */
    g_alert_queue = xQueueCreate(ALERT_QUEUE_LEN, sizeof(alert_msg_t*));

    /* Criar mutex e lista de redes seguras */
    g_secure_list_mutex = xSemaphoreCreateMutex();
    secure_list_init();

    /* Heartbeats iniciais */
    monitor_heartbeat = xTaskGetTickCount();
    alert_heartbeat = xTaskGetTickCount();

    /* Criar tasks */
    xTaskCreatePinnedToCore(task_monitor, "task_monitor", MONITOR_STACK, NULL, MONITOR_TASK_PRIO, &g_task_monitor, 1);
    xTaskCreatePinnedToCore(task_alert_handler, "task_alert", ALERT_STACK, NULL, ALERT_TASK_PRIO, &g_task_alert, 1);
    xTaskCreatePinnedToCore(task_supervisor, "task_superv", SUPERV_STACK, NULL, SUPERV_TASK_PRIO, &g_task_superv, 1);

    ESP_LOGI(TAG, "Sistema em execução.");
}
