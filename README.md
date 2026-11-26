# 跨命名域服务发现的缺失证明与订阅修复

合成名称以点分层级。前缀 P 覆盖 P 及 P. 开头的名字。代次只在相同前缀内比较。

## 输入消息

每个 JSONL 文件是一段独立输入记录。每行包括整数秒点 at、消息名称 kind 与对象 record。at 代表中间件收到消息的时刻，同一秒内按行序提交。业务时间和对应回执引用写在 record 中。

- **delegate**　prefix、holder、epoch 确定一次管辖，父级控制端提供。
- **service**　holder/epoch 对 name 给出 endpoint、tenants、until、revision；endpoint 为 null 表示明确撤回。
- **cover**　holder/epoch 声明确切 prefix 已完整覆盖至 revision。 until 为覆盖证明的过期秒点。
- **query**　tenant、name 和 query 身份，mode 为 start 或 inspect。
- **watch**　client 为 tenant/name 建立或恢复订阅，after 为实际处理的序号，0 为初次。
- **trim**　发现服务压缩通知的保留前缀。
- **restart**　模拟服务重启。
- **inspect**　按 client 或 name 查询。

## 示例

- missing-before-registration.jsonl
- ownership-turns-during-recovery.jsonl

## 读取演练资料

运行环境为 Python 3.11，只使用标准库。在根目录运行以下命令可核对文件格式及读取接口。

    python3 scenario_reader.py examples
    python3 -m unittest discover -v

资料读取器会按文件统计各类参与方消息的数量。演练记录只描述各参与方交给系统的输入。

## 联合发现实现

核心实现在 `federated_discovery.py`，只使用 Python 3.11 标准库：

- `DiscoveryService`：委托代次、端点/撤回、cover 证明、查询版本、watch 游标、trim/restart 和值班检查。
- `DiscoveryCache` / `ControlledCache`：租户隔离、TTL、失效通知和资格重验。
- `DiscoveryAgent` / `Agent`：仿真代理侧缓存与“实际处理到的通知位置”。
- `scenario_runner.py`：把 JSONL 场景跑成确定性 JSON 回执。
- `http_service.py`：可选的本机 HTTP/JSON 服务；所有名字和端点仍是合成标识。
- `discovery_service.py`、`discovery/`、`service.py`、`solution.py`、`agent.py`、`client.py`、`cache.py` 是常用导入路径别名。

运行全部测试：

```bash
python3 -m unittest discover -v
```

运行演练并输出每条消息的简要状态：

```bash
python3 scenario_runner.py examples
python3 federated_discovery.py examples/missing-before-registration.jsonl --full
```

启动值班/查询 HTTP 服务：

```bash
python3 http_service.py --host 127.0.0.1 --port 8765
curl 'http://127.0.0.1:8765/v1/inspect?name=tools.hand.joint'
```

## 结果状态约定

查询结果不会把“空”都当成同一件事：

- `found`：当前代次中存在对该租户可见且未过 `until` 的端点；同时签发 `qualification` / `start_token`。
- `missing`：当前负责该名字的代次给出了有效 cover，且 cover 已覆盖相关修订；结果才有 `until`、`cacheable=true` 和 `negative_token`。
- `explicit_empty`：当前管辖方已明确撤回，但 cover 尚未追齐时，可知道现在为空，却不能签发带 TTL 的负缓存结论。
- `coverage_pending`：还没有有效、未过期且追平修订的覆盖证据；不能把它当成“没有服务”。
- `upstream_unreachable`：管辖方/上游被标记为失联；这不是缺失证明。
- `authority_pending`：委托代次已转移，但新管辖方尚未给出当前代次的端点或 cover。旧内容只放在 `historical_basis`，旧 `start_token` 不能再启动调用。

`tenant_scoped_proof=true` 表示 cover 之后唯一的新修订属于另一租户且对当前租户不可见；结果仍按租户隔离，不会包含另一租户端点。

## 订阅、保留点和重同步

全局通知序号从 1 开始。`watch.after` 是客户端**实际处理过**的最大序号：

- `after >= trim_through`：可从保留区间续读，只返回与该租户、名字或前缀相关且已按租户脱敏的事件。
- `after < trim_through` 或游标超前：返回 `must_resync=true` 和单个原子 `snapshot`，不返回跨代次增量。
- 快照带 `consistency_token`。若重同步期间委托代次再次变化，携带旧 token 的 watch 会得到 `snapshot_generation_changed_during_resync`，必须改用最新原子快照，不能把两个代次拼成一张目录。
- `inspect.client` 会说明该订阅为什么能续接或必须重取，并列出已失效的旧资格；`inspect.name` 会给出当前管辖方、代次和欠覆盖证据的位置。

`restart` 模拟持久目录状态和通知保留点保留、瞬态连接重建；因此重启后仍可诊断游标是否落在保留区间。
