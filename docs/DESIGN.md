# Scopepack 设计说明

## 1. 问题与不变量

同一份虚构行程数据被三类用途消费：财务结算、安全调查、城市分析。每个用途只被授权一个
字段子集；订阅按版本续约，**续约只能收紧字段集合，不能放宽**。系统必须始终满足：

| 不变量 | 含义 |
| --- | --- |
| I1 交付最小化 | 任何一个交付产物、任何一段已发出的响应字节，都不含该合约未授权的字段。 |
| I2 收紧即时生效 | 用途策略收紧后，新的下载立即被拒；已经在传输中的慢速下载必须在有限字节内中止。 |
| I3 地址不复活 | 收紧前签发的下载地址（grant/URL）在收紧后不能因为节点缓存而继续返回旧字段。 |
| I4 历史可审计 | 已交付的确认、已发出的 grant、旧产物都保留可查；保留不等于当前有效，也不得被常规清理删除。 |
| I5 幂等 | 续约重试、确认重放、构建重复完成都不会产生第二份合约/第二条确认/第二份产物。 |
| I6 构建可恢复 | 构建器崩溃或租约过期后，另一个构建器能接手，且最终只有一份产物。 |

## 2. 核心决策：构建期按用途分包，而非读取期裁剪

### 备选方案

**A. 读取期裁剪**：交付层保存全字段源数据，每次下发时按合约过滤列。

**B. 构建期按用途生成独立包**（本项目采用）：每个 `(用途, 策略版本, 数据版本)` 组合
渲染一份只含被授权字段的不可变产物。

### 否决 A 的理由

1. **交付层被迫持有全字段并集。** 要服务所有用途，共享缓存必须保存源数据的全部列，
   包括司机姓名、电话、GPS 轨迹等。任何一次缓存落地、磁盘快照、备份、边车容器复制都会
   把高敏感字段带到分发层。这与「分发层只应接触被授权数据」直接冲突。
2. **慢速下载把并集长期暴露在连接上。** 即使读取时裁剪，响应体在到达消费者之前仍然
   经过分发进程的内存与 socket；中途撤权时，裁剪逻辑必须与流式写入竞争。构建期裁剪
   使这一层根本不存在正确的失败模式。
3. **缓存无法证明自己安全。** 读取期方案下，缓存命中与否、缓存内容是否含禁用列需要
   额外审计；构建期方案下，产物本身就是合约的证据，摘要可签名。
4. **故障域更小。** 裁剪 bug 会让所有用途同时泄露；分包后一个用途的渲染 bug 只影响该用途。

### 接受 B 的代价与缓解

- **存储/构建成本随用途增长。** 用唯一约束 `(purpose_id, policy_version_id, dataset_version_id)`
  去重；策略收紧只重建受影响用途；未变化的策略版本不会重复构建。
- **字段集合在构建时固定。** 这是特性而非缺陷：产物摘要与 manifest 可签名，节点可以
  校验「我缓存的字节确实等于登记服务批准的那份」。
- **仍需下发期复核。** 构建期裁剪只保证产物不含禁用字段，不能保证产物在**签发之后**
  仍然被允许交付。因此每个下载节点：

  1. 取缓存前向登记服务确认 grant/合约/包状态；
  2. 缓存字节必须与登记服务给出的摘要和大小一致（构建器签名校验）；
  3. 流式下发过程中每 `SCOPEPACK_EDGE_RECHECK_MS`（默认 350ms）重新鉴权一次，
     拒绝后立即中止连接并清理该包缓存；
  4. 后台清理线程每 2s 对照登记服务状态清除不再可分发的缓存。

  换言之：**构建期裁剪解决「哪些字节可以存在于分发层」，下发期逐块复核解决
  「这些字节现在是否仍被允许交付」。**

## 3. 进程与信任边界

```
            admin (Web 控制台 / API)
                     │ X-Admin-Token
                     ▼
┌──────────────────────────────┐        ┌──────────────────────┐
│ registry  :7101              │◄───────│ builder  :7102       │
│ · 策略版本 / 合约 / grant     │ 服务令牌 │ · 领取租约            │
│ · 授权判定（唯一决策点）       │        │ · 渲染不可变产物       │
│ · SQLite WAL 控制库（唯一写者）│        │ · 上报摘要+manifest   │
│ · 审计 / 确认 / 事件          │        └──────────────────────┘
└───────┬──────────────┬───────┘
        │ 服务令牌       │ 服务令牌
        ▼              ▼
┌──────────────┐  ┌──────────────┐
│ edge-a :7111 │  │ edge-b :7112 │   消费者持有订阅 Bearer token
│ 缓存+分块下发  │  │ 缓存+分块下发  │──────────────┐
└──────────────┘  └──────────────┘              │
        ▲─────────────────────────────────────────┘
                     POST /downloads (Bearer + grant_id)
```

- 控制库只由 registry 写入；builder 与 edge 通过 HTTP + `X-Service-Token` 访问，
  不直接碰数据库。
- 授权判定只有一处：`registry.grant_status()`。builder 和 edge 都不能自行决定放行。
- builder 上报完成时，registry 会再次校验 manifest 的字段集合与当前策略完全一致，
  拒绝被篡改的构建器（测试 `test_07`）。
- 产物签名：`HMAC(pseudonym_secret 派生密钥, content_sha256 + ":" + manifest 指纹)`，
  edge 拉取后校验摘要与大小；签名随包元数据下发，供审计比对。

## 4. 数据模型与状态机

### 4.1 策略版本

`policy_versions` 每个用途同时只有一个 `active`（部分唯一索引保证）：

```sql
CREATE UNIQUE INDEX idx_policy_one_active
  ON policy_versions(purpose_id) WHERE status = 'active';
```

应用新策略是一个事务：旧 active → `retired`，插入新版本 + 逐字段规则（允许/拒绝 + 理由），
创建/复用新包，把旧包标记 `blocked`。**放宽请求在进入事务前就返回 409
`widening_not_allowed`**，并列出被放宽的字段。

续约时还会做第二次收窄：新合约字段 = 新策略字段 ∩ 旧合约字段。因此即使策略本身
没有变化，消费者也不可能通过续约拿到比上一版更多的字段。

### 4.2 包生命周期

```
pending ──lease──► building ──complete──► ready ──policy changed──► blocked ──replacement ready──► retired
   ▲                   │                    │                                            (artifact 保留，不可下载)
   └──rebuild(force)───┴──fail──► failed ───┘
```

- `ready` 且其 `policy_version_id == 当前 active 策略` 才 `downloadable=true`。
- 策略变更瞬间旧包变 `blocked`（立刻不可下载），新包 `ready` 时旧包转 `retired`。
- **迟到的旧策略构建**：如果构建器在策略切换后才完成一个旧策略的产物，registry 不发布它，
  而是把文件改名为 `*.retired-<policy_id>` 并置为 `retired`，同时不触碰新包的任务
  （`builder_complete` 中 `archived_superseded` 分支）。排队中的旧策略任务在下次领取时
  直接取消。
- 产物文件永不删除；`retention_note` 说明保留原因。

### 4.3 合约

每个订阅每次续约产生一个新版本；旧版本 `superseded`，其 grant 全部撤销，但记录保留。
`change_kind` ∈ `initial | unchanged | narrowed`。`renewal_requests(subscription_id,
renewal_key)` 单独记录幂等键——即使这次续约字段没变、没有产生新合约，重放同一个 key 也
能返回当时的结果，而不会在策略变化后返回旧合约：重放总是返回**当前生效合约**并附
`replayed_contract_version`。

### 4.4 Grant

- 有 TTL（`SCOPEPACK_GRANT_TTL_SECONDS`，默认 120s），绑定包、合约、订阅和节点。
- `issue_key` 幂等；若该 key 对应的 grant 已被撤销，返回 409 `renewal_required`，
  绝不复活一张死票据。
- 撤销原因：`policy_narrowed`（策略变更）、`contract_superseded`（续约）、
  `package_retired`（旧产物归档）。

### 4.5 确认（ack）

分类：
- `current`：合约仍 active、包 `ready`、策略版本匹配 → `counts_current=1`。
- `historic_retained`：旧消费端、已 superseded 的合约、已 retired 的包、已撤销的 grant
  → 保留，`counts_current=0`。
- `integrity_mismatch`：上报摘要与 manifest 不符 → 隔离（`retained=0`）。

`ack_id` 全局唯一；重复提交返回 `duplicate` 与原分类。**先做归属校验再做去重**：
消费者 token 与 grant 订阅不一致时返回 403，避免用别人的 ack_id 探测或污染记录；
同一 ack_id 指向不同 grant 返回 409。

## 5. 故障与并发处理

| 场景 | 处理 |
| --- | --- |
| 慢速下载中途收紧策略 | 流式生成器每块前复核；拒绝时抛错断开连接，edge 记录 `stream_aborted` 并立即清缓存。测试断言收到的字节数小于完整大小。 |
| 下载地址来自缓存 | 缓存键是 `package_key`（含策略版本），旧包在策略变化后不可下载；清理线程与即时清理双保险。 |
| 续约请求超时后重试 | `renewal_key` 去重，返回同一合约（或当前合约）；不产生第二版。 |
| 续约响应丢失、消费者仍用旧合约 | grant 接口检查策略版本，返回 409 `renewal_required`。 |
| 构建器崩溃 | 租约（token + 过期时间 + 心跳）到期后可被重新领取；完成接口校验租约 token，旧构建器迟到完成返回 409 `lease_conflict`；产物原子替换，只有一个最终文件。 |
| 构建失败 | job → `failed`，包 → `failed` 并记录原因；管理员 rebuild 重新入队。 |
| 构建器被攻破/字段被篡改 | 完成接口比对 manifest 字段与策略字段、包 key、产物路径前缀、文件存在性；不一致 409 拒绝。 |
| 节点缓存被篡改 | 拉取时校验摘要与大小，不符返回 502 且不落盘；每次命中缓存也会复算摘要。 |
| 登记服务不可达 | edge 复核 **fail-closed**：已开始的流也中止（`authorization_unavailable`），清理线程在状态不可得时跳过（不误删）。 |
| 并发续约同一 key | 去重查询在写锁内再做一次。 |
| 并发构建同一包 | `BEGIN IMMEDIATE` 租约；`build_jobs.package_id` 唯一。 |
| SQLite 嵌套事务 | SAVEPOINT 嵌套封装（`common/db.py`），避免 "transaction within a transaction"。 |

## 6. 接口一览

### 登记服务（registry，:7101）

管理面（`X-Admin-Token`）：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/v1/admin/overview` | 用途、策略、包、合约、节点汇总 |
| GET | `/api/v1/admin/purposes` | 用途列表 |
| GET | `/api/v1/admin/purposes/{code}` | 用途详情（字段、规则、包、合约） |
| POST | `/api/v1/admin/purposes/{code}/preview` | 预览变更影响，不落库 |
| POST | `/api/v1/admin/purposes/{code}/policy` | 应用新策略（只允许收紧） |
| POST | `/api/v1/admin/purposes/{code}/rebuild` | 排队/强制重建 |
| GET | `/api/v1/admin/packages/{id}` | 包详情 + `authorization_basis` |
| GET | `/api/v1/admin/audit` | 审计事件 |
| GET | `/api/v1/admin/nodes` | 节点健康与缓存统计 |

消费者面（Bearer 订阅 token）：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/consumer/v1/renew` | 续约；`renewal_key` 幂等 |
| GET | `/consumer/v1/contract` | 当前有效合约 |
| POST | `/consumer/v1/grants` | 申请下载票据；`issue_key` 幂等 |

服务面（`X-Service-Token`）：

| 方法 | 路径 | 调用方 |
| --- | --- | --- |
| POST | `/edge/v1/authorize` | edge 鉴权（支持 `probe` 复核） |
| GET | `/edge/v1/packages/{key}/state` | edge 清理线程 |
| POST | `/edge/v1/events` | edge 上报事件 |
| POST | `/edge/v1/acks` | 消费者或 edge 提交确认 |
| POST | `/edge/v1/nodes/heartbeat` | edge 心跳 |
| POST | `/builder/v1/jobs/lease` | builder 领取任务 |
| POST | `/builder/v1/jobs/{id}/heartbeat` | builder 续租 |
| POST | `/builder/v1/jobs/{id}/complete` | builder 完成上报 |
| POST | `/builder/v1/jobs/{id}/fail` | builder 失败上报 |
| GET | `/builder/v1/packages/{key}/artifact` | edge 预取产物（服务令牌） |

### 构建器（builder，:7102）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/healthz` | 当前任务、统计 |
| GET | `/artifacts/{package_key}` | 产物字节（服务令牌，附摘要校验） |
| POST | `/builder/v1/wake` | 立即轮询任务队列 |

### 下载节点（edge，:7111 / :7112）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/healthz` | 节点状态、会话数、缓存大小 |
| POST | `/downloads` | Bearer + `grant_id`；支持 `Range: bytes=N-`，返回 200/206，头部带摘要、字段、合约版本 |
| GET | `/admin/cache` | 缓存清单与清理历史（服务令牌） |
| GET | `/admin/sessions` | 活跃下载会话 |
| GET | `/admin/purge` | 手动清理（运维用） |

## 7. 控制台

由 registry 直接托管（`/`、`/static/*`），中文界面：

- 用途列表 + 节点健康 + 设计说明面板；
- 每个用途：字段网格（允许/拒绝及理由）、包列表（状态徽标、可下载性、保留说明）、
  合约表、活动流；
- 「编辑策略」抽屉：勾选字段（只能取消勾选）、备注、**预览**（被移除字段、受影响的
  合约与订阅、待撤销 grant 数、活跃下载会话数、预计产物大小）、应用；
- 「授权依据」抽屉：策略版本与逐字段规则、引用该包的合约、grant、下载事件、确认、
  manifest 与签名；
- 每 5s 轮询刷新，编辑中的表单不会被后台刷新覆盖。

## 8. 测试覆盖（17 项集成测试）

`tests/test_policy.py`
1. 续约构建出仅含授权字段的包（manifest `trim_at_read=false`，excluded 列表完整）；
2. 产物中不存在被拒列；
3. 续约/策略均不可放宽（409 + 字段列表）；
4. 预览不改变状态；
5. 策略收紧：旧包 blocked→retired、grant 撤销、缓存的旧地址被拒、需续约；
6. 重放旧 renewal_key 不会复活旧合约；
7. 被篡改的构建器上报被拒；
8. 旧策略的构建在策略切换后才完成：产物改名归档为 `retired`、不可下载、不影响新包。

`tests/test_delivery.py`
1. 缓存按合约字段服务；
2. 慢速下载中途收紧 → 连接中止、字节不完整；
3. Range 断点续传（206 + Content-Range）；
4. 重复 ack 幂等、越权 ack 403、摘要不符隔离；
5. 旧消费端 ack 归为 `historic_retained` 且不计数；
6. 策略变化后节点缓存被清理；
7. 过期 grant 返回 403。

`tests/test_builder.py`
1. 构建器崩溃 + 租约过期后的接管：单产物、单 done 任务、attempts ≥ 2；
2. 构建失败可重建。

## 9. 生产化注意事项（本项目为演示实现）

- 令牌为演示默认值，全部可用环境变量覆盖；真实部署应使用密钥管理服务。
- 服务间 HTTP 为明文，生产应加 mTLS；产物签名目前用 HMAC 对称密钥，跨信任域应改为
  非对称签名。
- SQLite 适合单机演示；多实例登记服务需外部数据库与分布式锁。
- 节点缓存目录应放在加密卷上；`retired` 产物按保留策略归档到冷存储。
- 控制台管理员令牌存于 `sessionStorage`，生产应接入 SSO 与细粒度 RBAC。
