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
