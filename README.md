# quackhole-rbac

**DuckDB 远程查询服务:quackhole P2P 隧道 + quack 应用层认证 + luajit RBAC 表级授权。**

数据永远留在服务器本地,外部客户端只拿到查询结果——无需公网 IP、无需开放端口、无需 VPN/证书。每个用户独立 token,角色到表级别的只读权限,写操作默认全拒。

```
外部客户端 ──quackhole(iroh P2P 加密隧道,免公网 IP)──▶ 你的服务器
              │                                            ├─ quack(应用层认证:token → 用户)
              └─ 只拿到查询结果                            ├─ luajit rbac.lua(角色 → 表级权限)
                                                           └─ DuckDB 数据文件(永不出门)
```

## 为什么是这三层

| 层 | 工具 | 职责 |
|---|---|---|
| 隧道层 | [quackhole](https://github.com/smithclay/quackhole)(DuckDB 社区扩展) | iroh P2P 加密通道,免公网 IP/端口/证书,谁有 ticket 谁能连 |
| 认证层 | [quack](https://duckdb.org/quack/)(DuckDB 官方协议) | `quack_authentication_function` 把 token 映射到用户 |
| 授权层 | [duckdb-luajit](https://github.com/alitrack/duckdb-luajit) + `rbac.lua` | `quack_authorization_function` 按角色做表级 SELECT 授权,写语句全拒 |

## 快速开始

### 依赖

- DuckDB ≥ 1.5.5(quackhole 要求;macOS/Linux/Windows 均可)
- Python ≥ 3.10 + `duckdb` 包(推荐用 uv:`uv venv && uv pip install duckdb`)
- 社区扩展会自动安装:luajit / quack / quackhole

### 1. 启动服务端(有数据的那台机器)

```bash
# 演示模式:自动建 sample 库 + 示例角色
python server/server.py --sample --token my-tunnel-tok

# 真实模式:连已有的 DuckDB 数据文件(如 MIMIC 词表层)
python server/server.py --db /path/to/mimic_standard.duckdb --token my-tunnel-tok

# Windows 上若 9494 被 WSL 中继占用,加 --port 9495
```

启动后输出 ticket(约 165 字符的 `qh1_...` 字符串),并存到 `--ticket` 指定的文件。**ticket 要像密码一样保管**——任何人拿到它都能连进隧道。

> 真实模式下,请先在库中预置 RBAC 表与权限(见下方"权限模型"),或修改 `server.py` 中的 seed 部分。

### 2. 客户端连接(任何网络位置)

```bash
# 查一张有权限的表
python client/client.py --ticket /path/to/ticket.txt --token researcher-tok \
    --sql "SELECT count(*) FROM r.mimic_icd_map"

# 跑完整验证矩阵(合法访问 + 绕过攻击)
python client/client.py --ticket /path/to/ticket.txt --matrix
```

## 两层认证:为什么客户端要先换 secret

quackhole 的隧道认证用的是 **ticket 里的共享 token**;quack 的应用层认证需要 **per-user token**。所以客户端连上隧道后,要先把 quackhole 自动创建的 secret 换成自己的 token,再重新 ATTACH——这样服务端的 authn 钩子才能把连接映射到正确的用户。`client.py` 已封装这一步(`as_user`)。

```python
# client.py 内部做的事(等价于 quackhole 文档的 long-form):
con.execute(f"CALL quackhole_attach('{ticket}', name := 'r')")
# 找到 quackhole 建的 secret:名字是 qh_<endpoint-id>,scope 是 LIST 类型
# DROP 掉它,用 per-user token 重建同名 secret,再 DETACH + ATTACH
```

## 权限模型

RBAC 元数据是四张表(由 `rbac.lua` 的 `setup` 自动创建):

| 表 | 作用 |
|---|---|
| `quack_tokens(auth_token PK, user_name)` | token → 用户 |
| `quack_sessions(sid PK, user_name)` | 活跃连接 → 用户(authn 钩子写入) |
| `user_roles(user_name, role)` | 用户 → 角色 |
| `role_perms(role, table_name, can_select, can_write)` | 角色 → 表权限 |

策略(`rbac.lua` 可配置):

- `protected` — 受控表清单(authz 逐表查权限)
- `allow_write = false` — **一切写语句拒绝**(推荐;开了才按 can_write 细粒度放行)
- `strict_write = true` — WITH 开头一律拒绝(防 `WITH x AS (SELECT 1) INSERT INTO t` 绕过)

### 示例角色(server.py seed)

| 角色 | 可读表 | 说明 |
|---|---|---|
| `researcher_role` | mimic_icd_map / lab_loinc_map / rxnorm_ndc_map / concept_std | 全量研究员 |
| `viewer_role` | 仅 mimic_icd_map | 受限查看 |
| `tunnel_role` | 仅 mimic_icd_map | 隧道首连的最小权限 |

## 验证结果(2026-09-01 实测)

13 个测试点全部符合预期,零绕过:

```
=== 合法访问 ===
✅ alice/researcher  读受权表          → PASS
✅ bob/viewer        读公开表          → PASS
✅ bob/viewer        读未授权表        → DENY: Authorization failed

=== 绕过攻击(quack_query 强制服务端执行) ===
✅ 自授角色(INSERT user_roles)        → DENY
✅ 篡改权限表(UPDATE role_perms)      → DENY
✅ 宏替换(CREATE MACRO rbac_authz)    → DENY
✅ 切换授权函数(SET GLOBAL)           → DENY
✅ 绕过后重试                         → DENY
✅ 写操作(INSERT)                     → DENY

=== 认证 ===
✅ 未注册 token                       → DENY: Authentication failed
```

## 已踩的坑(重要)

1. **quackhole 的 secret 名是 `qh_<endpoint-id>`**,不是 `__default_quack`;`duckdb_secrets().scope` 返回 **LIST** 类型,要取 `[0]`
2. **绕过测试必须用 `quack_query`**(强制服务端执行);普通 ATTACH 下 `INSERT INTO user_roles` 会在客户端本地执行,测不到服务端策略
3. 服务端 `quack_tokens` 里必须注册隧道 token(映射到最小权限角色),否则客户端 attach 首连就被拒
4. `luajit_module` 编译和调用必须在**同一连接**;macOS arm64 的 luajit 社区扩展可直接 `INSTALL luajit FROM community`
5. iroh 公共中继免费但**无 SLA**,大规模上量要自建 relay
6. **hooks 要在 `LOAD quack` 之后 SET GLOBAL**——quack 未加载时设置 `quack_authentication_function` 会被静默丢弃(server.py 已加启动断言防这个坑)
7. **Windows 上 9494 端口常被 WSL 的 localhost 中继(wslrelay)抢占**——Windows 侧 serve 建议 `--port 9495` 避开;同一台机器 serve+client 会报 "Connecting to ourself is not supported",需跨机器/跨 WSL 测试
8. **Windows 原生 python 不识别 `/tmp` 和 `/d/...` 路径**(那是 git-bash/WSL 的写法)——ticket/db 路径请用 `D:/...` 或绝对 Windows 路径

## 目录结构

```
server/
  server.py          # 服务端:RBAC + quack hooks + quackhole,支持 --sample/--real
  rbac_mimic.lua     # MIMIC 词表层策略(protected = 4 张 MIMIC 表)
  rbac_sample.lua    # 演示策略(protected = secret_data/public_data)
client/
  client.py          # 客户端:attach + per-user 换 token + 查询/验证矩阵
docs/
```

## 安全边界(务必读)

- 授权钩子基于 **SQL 文本前缀**判断语句类型,非解析器——官方文档亦承认 `WITH` 型绕过,靠 `strict_write=true` 兜底
- 权限元数据表与数据同平面,靠"禁写"保护;管理员加权限请在**服务器本地会话**执行
- 无行级安全/列掩码(不能改写查询)
- 生产使用请加:每用户独立 ticket、quack 鉴权 + 审计表(`audit_table`)、自建 iroh relay

## License

MIT(本仓库为集成示例;quackhole/iroh MIT,quack DuckDB 官方,duckdb-luajit MIT)
