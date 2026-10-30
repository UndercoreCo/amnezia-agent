# Amnezia Config API 1.1.2

Expiry can cross a state/runtime RPC boundary. Reconciliation now validates the
remaining live peers at readback and retries only witnessed deadline crossings,
at most three attempts. Unexpected peers, live-peer loss and container epoch
changes still fail closed. Offline permission is checked after native observation
so normal expiry cannot create an identity conflict. Keys, exports, SQLite schema,
API contracts, offline limits and the independent runtime watchdog are unchanged.
Periodic failures log only a safe fault code; a failed shutdown RPC no longer
hides the initiating error. See the release notes for validation and deployment scope.

Current source releases use the [independent build and release procedure](../../docs/infrastructure/independent-releases.md).
It produces a complete allowlisted archive with a per-file manifest and checksum;
local candidates are not production releases. Historical patch/install scripts
below are not an updater for the current tree. Runtime data and credentials stay
outside source bundles. Publication is a separate approved operation.

Offline OpenAPI, baseline совместимости и проверки реальных HTTP-ответов: [contracts](../../contracts/README.md). Тестовые зависимости — `../../contracts/requirements.lock`; production requirements не менялись.

Separate adapter for Undercore-managed AmneziaWG configurations. Existing Amnezia containers and clients are out of scope. Source features and live availability are different: issuance and protocol switching depend on Laravel flags. Deployment history starts in [the deployment report](../../docs/release/deployment-2026-09-23-amnezia.md); current publication records are in [pending-release](../../docs/release/pending-release.md).

## Роль приложения

Laravel вызывает HTTP-фасад по HTTPS с отдельным Bearer. Фасад передаёт фиксированные команды непривилегированному awg-agent по Unix socket. Agent хранит состояние и обращается к отдельному root runtime executor, который работает только с dedicated AmneziaWG-контейнером. Это локально подготовленное разделение; порядок перехода — [AWG privilege boundary](../../docs/infrastructure/awg-privilege-boundary.md). Private keys не выдаются в metadata и не сохраняются в Laravel. Общая [карта системы](../../docs/system-overview.md), [карта API](../../docs/api-map.md).

Код: `app/main.py` — HTTP, `agent.py` — агент, `domain.py` — состояние и операции, `backend.py` — фиксированные Docker-вызовы, `export.py` — гостевой AmneziaVPN экспорт. `deploy/prepare.py` готовит настройки узла; `deploy/` содержит отдельные systemd, Compose и nginx примеры. HTTP-выдача OpenAPI отключена; контракты проверяются synthetic tests, описание находится в README и исходниках. Не запускайте prepare поверх действующего узла для простой смены адреса.

## Boundaries

- `app.main`: unprivileged HTTP service, loopback-only, Bearer auth on every route,
  no CORS, no response caching, bounded input, no arbitrary operations or shell.
- `app.agent`: unprivileged awg-agent, single state writer enforced by flock.
  HTTP UID is checked at the socket. `app.runtime_client` crosses a second
  UID-checked socket to `app.runtime`: root executor, fixed container
  `undercore-awg-api` and interface `awg0`, no caller-selected Docker command.
  Root/Docker authority remains only in the trusted executor.
- SQLite stores durable reservations, peer identities, deadlines, operations and
  encrypted client keys. Encryption key lives separately, readable by root and awg-agent only.
  The server private key is in root-only static server configuration. No secrets
  in logs, Laravel DB, queue payloads or API metadata.
- Each client has its own private/public keys and PSK. Re-download/renewal retain
  keys. Only explicit replacement changes them. Inactive clients retain addresses
  so that delayed requests cannot attach to a reused address.
- The independent agent sweeps expiry every 15 seconds without HTTP/Laravel.
  Every tunnel-container boot starts with zero peers. Reconciliation restores
  only unexpired, enabled, non-conflicting peers. An agent failure stops only its
  dedicated tunnel; the executor enforces peer deadlines and a 90-second apply
  lease independently. systemd watchdog and ExecStopPost cover hangs/crashes.
  Runtime restart is operator-controlled after failure; see the boundary runbook.
- Never edit the managed container using Amnezia's administrative application.
  Missing peers on the same boot become conflicts. Unknown peers stop automatic
  reconciliation. A service restart is not an administrative replacement action.

## Reconciliation cost (1.1.1 candidate)

Health reads verify the running container and server identity without applying
configuration or refreshing the executor lease. The 15-second state sweep and
independent expiry/watchdog remain active. Mutations and exports still reconcile.
Native reads are batched into one fixed shell command (no caller-provided script).
The server private key is filtered in-container; native PSKs are compared only
inside the root executor and are never included in snapshot RPC or HTTP output.
Before apply, actual native settings (including PSKs, addresses, listen port and
AWG parameters) are compared with the desired projection. Unchanged settings
skip syncconf. Successful apply RPC still refreshes the 90-second executor lease
and its in-memory peer deadlines even when no native write is required.
Container identity/restart races and peer drift are checked on every observation;
there is no long-lived cache of assumed native configuration. No DB migration,
new public endpoint, token change or client reimport is required.

## HTTP contract

Uses the existing cabinet gateway shape (`wgapi_<UUID hex>`, `account-v1`, UTC
millisecond timestamps). `GET /v1/health`, `GET/POST /v1/clients`, `GET
/v1/clients/{id}`, `GET /v1/clients/{id}/configuration`,
`GET /v1/clients/{id}/amnezia`, `POST
/v1/clients/{id}/{renew,replace,enable,disable}`.

Create: `external_id`, `device_id`, `name`, `expires_at`. Replaying the same
external identity with different creation fields returns 409. Renew: absolute
`expires_at` + `idempotency_key`. Replacement also requires
`expected_external_id` and `allow_create`. Lost responses reuse durable key
material. Old renewal replays never shorten a newer deadline. Disabled clients
remain disabled after renewal. Errors expose safe codes only.

Exports: AmneziaWG `.conf` (and its QR) plus guest `.vpn`/`vpn://` for AmneziaVPN.
Both use the same client identity, PSK, address and MTU 1280. Guest export includes
only allowlisted connection fields, never SSH credentials, API tokens or server
private keys. Apple mobileconfig is not supported. The native envelope uses Qt
qCompress framing and URL-safe base64, independently implemented against official
4.8.18.0 and 5.0.3.0 source. macOS 4.8.18 accepted a synthetic file up to the import
preview; mobile/client connection acceptance is still pending. Unverified AWG
parameter generations fail export with 422 instead of being silently dropped.
Client configuration includes IPv4 and IPv6 default routes; this deployment routes
IPv4 and blocks forwarded IPv6. Mobile app import/IPv6 leak checks are release
acceptance gates; a Linux tunnel test does not replace them.

## Installation (operator, after acceptance)

1. Choose and verify unused subnet/UDP port, domain/TLS, allowed service-network
   sources and a compatible image pinned by digest. Do not use floating `latest`.
   `deploy/prepare.py` requires an explicit digest and refuses existing output.
2. Stage code under `/opt/amnezia-config-api/releases/<version>` and create `current`.
   Install `requirements.lock` into `/opt/amnezia-config-api/venv`; run tests.
3. Create separate non-login users/groups awg-api and awg-agent. Neither may
   belong to docker/sudo/admin; only awg-agent additionally joins awg-api.
   Prepare files only for a new node. For existing nodes preserve all DB/keys.
4. Apply the ownership matrix in the [boundary runbook](../../docs/infrastructure/awg-privilege-boundary.md):
   state DB belongs to awg-agent, server key stays root-only, encryption key is
   readable only by the state agent, HTTP token only by awg-api. Code/venv/units
   remain root-owned. Never recreate the unrelated `amnezia-awg2` container.
5. Install the complete matching runtime/agent/HTTP code and three units during
   an approved maintenance window. Start runtime, then agent, then HTTP. Check
   expiry, recovery, Linux permissions and actual systemd watchdog first on an
   isolated node. Do not deploy a partial agent update or reuse historical scripts.
6. Configure cabinet `AWG_API_URL`, `AWG_API_KEY`, then `AWG_API_ENABLED=true` only
   after acceptance. Start `worker-amnezia` with compose profile `amnezia`.
   `AWG_SALES_ENABLED=true` separately opens new purchases, trials and grants;
   set only this flag to false to pause new issuance while preserving service.
   A separate worker is required; the default worker does not consume this queue.
7. Monitor authenticated health, expiry sweep/watchdog, queue age and free IPs.
   Kubernetes/multiple agent processes are not supported in this first version.

Back up the SQLite database consistently (SQLite backup API or stop the agent),
`node.json`, encryption key, server-only config, token and pinned image metadata.
Encrypt backups, restrict access and test restoration on an isolated host.
Never restore an old customer DB over a live one. Disabling new sales alone must
not stop expiry or service for already-issued configurations.

## Validation

```
python -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/python -m pytest -q
```

Tests use synthetic keys, temporary stores and a fake runtime. They cover lost
responses, durable replay, encryption, conflicting intent, expiry without HTTP,
restart, disable/renew, ownership checks for replacement, unknown peers, input
limits and authentication. A separate isolated Docker pilot validates the real
userspace AmneziaWG runtime before any production enablement.

## Диагностика — подготовлено локально 01.10.2026

`app/diagnostics.py` оборачивает HTTP-приложение: корректный единственный
`X-Request-ID` принимается только после авторизации; иначе генерируется новый.
Header есть на успехе и ошибке; JSON DTO/command schema/security сохранены.
`uvicorn.error.diagnostics` пишет JSON с operation/status/duration, без body,
URL, ключей, имён или customer IDs. RPC/native correlation не добавлялась.

Runtime ещё не обновлялся. Выпуск требует всего согласованного набора файлов,
включая новый модуль; исторические patch/deploy scripts не применять к новому
дереву. Старые клиенты без header работают. Проверки: `python -m pytest -q`.
Граница доверия, журнал и release gates: [request-diagnostics](../../docs/infrastructure/request-diagnostics.md).

## Локальное усиление границы 01.10.2026

Агент проверяет Linux SO_PEERCRED: запросы допускаются от UID awg-api либо root.
Группа socket сама по себе больше не даёт доступ другому UID. Полный запрос
должен поступить за 2 секунды, а не за 2 секунды на каждый фрагмент; лимит
16384 bytes, одна JSON строка и строгие operation поля сохранены. Ошибочный
запрос не выполняет Engine; длительность операции по-прежнему отдельно
ограничивают backend timeouts и systemd watchdog. HTTP unit лишён capabilities;
обе units получили дополнительную защиту kernel/control groups/SUID/realtime.

Root agent и доступ к Docker daemon сохраняются. Они не становятся безопасной
песочницей от произвольного исполнения в агенте только из-за этих настроек.
Dedicated tunnel всё ещё останавливается при потере гарантии expiry; менять
это на fail-open запрещено. S3 частично снижен, не закрыт полностью.
Linux SO_PEERCRED, service units, watchdog/crash/restart и запрет доступа к
чужим контейнерам должны пройти отдельный изолированный Linux стенд перед
публикацией. Runtime не обновлялся. [Реестр HIGH](../../docs/release/vpn-high-findings-2026-10-01.md).

## Следующий шаг: отдельный runtime executor

Локально подготовлены unprivileged state agent и узкий root executor. Предыдущая
запись об усилении root-agent выше — история первого шага. Текущие права, rollout
и незакрытые Linux/native gates: [граница AWG](../../docs/infrastructure/awg-privilege-boundary.md).
S03 остаётся открытым до их приёмки; runtime production не обновлён.
