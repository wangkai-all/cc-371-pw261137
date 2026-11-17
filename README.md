# Scopepack — 按用途分包的虚构数据分发系统

Scopepack 演示一条完整的数据加工与分发链路：同一个虚构行程数据集，被不同用途的消费者
（财务结算 / 安全调查 / 城市分析）以各自被授权的字段集合获取；续约时字段只能收紧，不能放宽。
包在高并发下载、慢速下载、续约中断、构建器崩溃、旧消费端重复确认等条件下仍然保持授权一致。

全部数据为虚构数据，固定随机种子生成。仅依赖 Python 3.11 标准库，无第三方包。

## 快速开始

```bash
python3 -m scopepack.dev up --reset
```

该命令会生成数据源、初始化 SQLite 控制库，并启动 **四个独立进程**：

| 进程 | 地址 | 职责 |
| --- | --- | --- |
| 订阅登记服务 registry | http://127.0.0.1:7101/ | 授权判定、策略版本、合约、授权票据、审计、Web 控制台 |
| 包构建器 builder | http://127.0.0.1:7102/ | 领取构建任务、按用途渲染不可变产物、上报摘要 |
| 下载节点 edge-a | http://127.0.0.1:7111/ | 缓存、分块下发、每块重新鉴权、断点续传 |
| 下载节点 edge-b | http://127.0.0.1:7112/ | 同上，用于验证跨节点一致性与缓存清理 |

默认凭据（可用环境变量覆盖，务必在生产中替换）：

- 管理员令牌 `dev-admin-token-change-me`（Web 控制台首次打开时输入）
- 服务间令牌 `dev-service-token-change-me`
- 消费者令牌写入 `var/consumer-tokens.json`（权限 0600）

浏览器打开 http://127.0.0.1:7101/ 即为控制台：可编辑每个用途的字段集合、预览影响、
触发重建、查看每份包的授权依据。Ctrl-C 停止全部进程。

不带 `--reset` 的重复启动会复用 `var/` 下已有状态。

## 消费者命令行

控制台之外，消费者侧由 `scopepack.consumer.agent` 模拟真实客户端：

```bash
# 续约（同一个 renewal key 重试是幂等的）
python3 -m scopepack.consumer.agent --consumer finance renew --renewal-key demo-1
# 查看当前生效合约
python3 -m scopepack.consumer.agent --consumer finance inspect
# 下载：自动取票、断点续传、校验摘要、落盘确认
python3 -m scopepack.consumer.agent --consumer finance download --node node-a --out downloads
# 重放本地暂存的确认（服务端按 ack 去重）
python3 -m scopepack.consumer.agent --consumer finance ack
```

## 运行测试

测试会自行在临时目录、随机端口上拉起四个进程，不触碰 `var/`：

```bash
python3 -m unittest discover -s tests -v
```

17 个集成测试覆盖策略收紧、缓存不泄露、慢速下载中途撤权、断点续传、票据过期、
构建器租约过期恢复与失败重试、旧策略构建迟到完成归档、续约重放、重复/旧消费端确认等场景。

## 关键设计决策

**按用途在构建期生成独立不可变包，而不是在读取时裁剪字段。**

若所有用途共享同一份交付缓存、在下发时按订约裁剪字段，缓存里就必须保存所有字段的并集；
缓存一旦被旁路、被复制或在下发中途崩溃，禁用字段就已经存在于交付层。慢速下载更是把这份
并集长时间暴露在连接上。相反，每个用途、每个策略版本、每个数据版本各生成一份只含被授权
字段的产物，交付层从物理上不可能持有未授权字段。代价是存储与构建成本随用途数增长，
因此用 `(purpose, policy_version, dataset_version)` 唯一约束复用产物，并在策略变更时只重建
受影响的用途。

即便如此，仍不能假设产物一签发就永久可用：节点上的旧缓存、已经发出的下载地址、
正在传输的连接都必须逐块复核。所以方案是「构建期裁剪 + 下发期逐块复核」二者并用。

完整论证、威胁模型、状态机与接口清单见 [docs/DESIGN.md](docs/DESIGN.md)。

## 目录结构

```
scopepack/
  common/     配置、HTTP 框架、SQLite 事务、策略与虚构数据生成
  registry/   订阅登记服务（schema.sql 在此）
  builder/    包构建器
  consumer/   下载节点 edge.py 与消费者 CLI agent.py
  web/        中文控制台（由 registry 直接托管）
  dev.py      本地四进程编排
tests/        集成测试与进程编排 harness
docs/         设计文档
```

运行时状态全部位于 `var/`（已忽略）：`registry.sqlite3`、`source/`、`artifacts/`、`edges/`。
