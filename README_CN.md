# quackhole-rbac

**DuckDB 远程查询服务:quackhole P2P 隧道 + quack 应用层认证 + luajit RBAC 表级授权。**

> 英文 README(默认语言)见 [README.md](README.md)。

DuckDB 数据文件始终留在服务器上;外部客户端通过加密 P2P 隧道连接,只拿到查询结果——无需公网 IP、无需开放端口、无需 VPN/证书。每个用户独立 token,角色到表级别的只读权限,写操作默认全拒。(被授权的用户可以读完整张表——没有行级/列级控制。)

```
外部客户端 ──quackhole(iroh P2P 加密隧道,免公网 IP)──▶ 你的服务器
              │                                            ├─ quack(应用层认证:token → 用户)
              └─ 只拿到查询结果                             ├─ luajit rbac.lua(角色 → 表级权限)
                                                           └─ DuckDB 数据文件(留在服务器)
```

## 为什么是这三层

| 层 | 工具 | 职责 |
|---|---|---|
| 隧道层 | [quackhole](https://github.com/smithclay/quackhole)(DuckDB 社区扩展) | iroh P2P 加密通道,免公网 IP/端口/证书,谁有 ticket 谁能连 |
| 认证层 | [quack](https://duckdb.org/quack/)(DuckDB 官方协议) | `quack_authentication_function` 把 token 映射到用户 |
| 授权层 | [duckdb-luajit](https://github.com/alitrack/duckdb-luajit) + `rbac.lua` | `quack_authorization_function` 按角色做表级 SELECT 授权,写语句默认全拒 |

## 快速开始

### 依赖

- DuckDB ≥ 1.5.5(quackhole 要求;macOS/Linux/Windows 均可)
- Python ≥ 3.10 + `duckdb` 包(推荐用 uv:`uv venv && uv pip install -r requirements.txt`)
- 社区扩展会自动安装:luajit / quack / quackhole

### 1. 启动服务端(有数据的那台机器)

```bash
# 演示模式:自动建 sample 库(secret_data / public_data)+ 演示角色
python server/server.py --sample --token my-tunnel-tok

# 真实模式:连已有的 DuckDB 数据文件
python server/server.py --db /path/to/your_data.duckdb --token my-tunnel-tok

# Windows 上若 9494 被 WSL 中继占用,加 --port 9495
```

启动后服务端把 ticket(约 165 字符的 `qh1_...` 字符串)写入 `--ticket` 指定的文件,并打印其长度与路径。**ticket 要像密码一样保管**——任何人拿到它都能进隧道,并在换 user token 之前以 `tunnel` 身份认证。

> 真实模式下,请先在库中预置 RBAC 表与权限(见下方"RBAC 模型"),或修改 `server.py` 中的 seed 部分。

### 2. 客户端连接(任何网络位置)

```bash
# 演示模式示例(对应 server.py --sample):token alice-tok,表 public_data
python client/client.py --ticket /path/to/ticket.txt --token alice-tok \
    --sql "SELECT count(*) FROM r.public_data"

# 真实模式示例:per-user token + 受服务库中的表
python client/client.py --ticket /path/to/ticket.txt --token researcher-tok \
    --sql "SELECT count(*) FROM r.public_data"

# 跑演示模式验证矩阵(合法访问 + 绕过攻击)
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

## RBAC 模型

RBAC 元数据是四张表(由 `rbac.lua` 的 `setup` 自动创建):

| 表 | 作用 |
|---|---|
| `quack_tokens(auth_token PK, user_name)` | token → 用户 |
| `quack_sessions(sid PK, user_name)` | 连接 → 用户(authn 钩子写入;是持久化的会话映射,不是活跃连接注册表) |
| `user_roles(user_name, role)` | 用户 → 角色 |
| `role_perms(role, table_name, can_select, can_write)` | 角色 → 表权限 |

策略(`rbac.lua` 可配置):

- `protected` — 受控表清单(authz 逐表查权限)
- `allow_write = false` — **一切写语句拒绝**(推荐;开了才按 can_write 细粒度放行)
- `strict_write = true` — 以 `WITH` 开头一律拒绝(防 `WITH x AS (SELECT 1) INSERT INTO t` 绕过,但也会误拒合法的 CTE 读)

### 预置角色

真实模式(由你的策略 lua 的 `protected` 清单驱动——复制 `rbac_sample.lua` 并编辑清单):

| 角色 | 可读表 | 说明 |
|---|---|---|
| `researcher_role` | `protected` 里除 RBAC 元数据外的全部数据对象 | 全量研究员 |
| `viewer_role` | 以 `s_` 开头的对象(公开展示层) | 受限查看 |
| `tunnel_role` | 仅第一张数据表 | 隧道首连的最小权限 |

演示模式(sample):`analyst` 可读 `public_data` 与 `secret_data`;`viewer` 仅 `public_data`;隧道身份仅读 `public_data`。

RBAC 元数据表(`quack_*` / `user_*` / `role_*`)在真实模式下不授予任何客户端。(演示模式下这 4 张元数据表**不在** `protected` 清单内——属演示模式的缺口,见安全边界。)

## 验证(演示模式矩阵,2026-09-01 实测)

`--matrix` 覆盖合法访问与一组绕过尝试(自授角色、篡改权限、宏接管、切换授权函数、写操作)。2026-09-01 这一跑的结果符合预期:

```
=== 合法访问 ===
alice/analyst   读 secret_data   → 返回行
bob/viewer      读 public_data   → 返回行
bob/viewer      读 secret_data   → DENY(授权)

=== 绕过攻击(quack_query 强制服务端执行) ===
自授角色          → DENY
篡改 role_perms  → DENY
宏接管           → DENY
切换授权函数      → DENY
绕过后重试       → DENY
写操作(INSERT)   → DENY

=== 认证 ===
未注册 token      → DENY(认证)
```

**这是一次带日期的测试运行,不是安全保证。** 矩阵只覆盖演示模式(硬编码演示 token/表),把一切异常都标成 `[DENY]`(不区分基础设施错误与授权拒绝),且下面的强制机制存在已知局限。

## 已踩的坑

1. **quackhole 的 secret 名是 `qh_<endpoint-id>`**,不是 `__default_quack`;`duckdb_secrets().scope` 返回 **LIST** 类型,要取 `[0]`
2. **绕过测试必须用 `quack_query`**(强制服务端执行);普通 ATTACH 下 `INSERT INTO user_roles` 会在客户端本地执行,到不了服务端策略
3. 服务端 `quack_tokens` 里必须注册隧道 token(映射到最小权限角色),否则客户端 attach 首连就被拒
4. `luajit_module` 编译和调用必须在**同一连接**;macOS arm64 的 luajit 社区扩展可直接 `INSTALL luajit FROM community`
5. iroh 公共中继免费但**无 SLA**,大规模上量要自建 relay
6. **hooks 要在 `LOAD quack` 之后 SET GLOBAL**——quack 未加载时设置 `quack_authentication_function` 会被静默丢弃(server.py 加了启动检查防这个坑)
7. **Windows 上 9494 端口常被 WSL 的 localhost 中继(wslrelay)抢占**——Windows 侧 serve 建议 `--port 9495`;同一台机器 serve+client 会报 "Connecting to ourself is not supported",需跨机器/跨 WSL 测试
8. **Windows 原生 python 不识别 `/tmp` 和 `/d/...` 路径**(那是 git-bash/WSL 的写法)——ticket/db 路径请用 `D:/...` 或绝对 Windows 路径

## 安全边界(务必读)

这是一个**策略强制的演示骨架,不是加固过的授权边界。** 代码评审确认的已知局限:

> **2026-10-13 v2 加固**(独立探针实测 + 代码评审复现,单元回归 `test/test_rbac_lua.py` 23/23 覆盖):
> - ✅ 大小写绕过(`SELECT * FROM SECRET_DATA`)已修复——大小写不敏感 + 词边界匹配
> - ✅ 未列名表零授权可读(allow-by-absence)已修复——`default_deny=true`:语句引用的任何**已存在**表/视图都必须有授权
> - ✅ 演示模式元数据暴露已修复——四张 RBAC 元数据表已进 `protected`
> - ✅ `SELECT luajit_s('rbac',{op:'grant'/'setup'})` 远程提权已封杀——authz 拒绝任何远程 `luajit_s` 调用
> - ✅ grant 静默失败已修复——回读验证,失败显式报 error
> - ✅ 视图检查盲区已修复——枚举已含 `duckdb_views()`


- **表检查是对原始 SQL 文本做大小写敏感的子串匹配,不是解析器。** 受保护表用大写引用(`SELECT * FROM SECRET_DATA`)会完全绕过检查;未列名的表可以在无任何授权的情况下被读;字符串字面量或注释里含表名会造成误拒。正确做法是对解析后、已解析的表引用做 default-deny 检查。
- **带副作用的 `SELECT` 被归类为读。** 若 `luajit_s` 可从远程 SQL 触达,客户端可用 `SELECT luajit_s('rbac', {op:'grant', ...})` 或 `{op:'setup'}` 写权限/执行 DDL;"一切写语句拒绝" 覆盖不到这些。(实际可达性取决于运行时。)
- **`luajit_s` 分发器暴露了 `grant` / `setup` / `authn`,没有任何管理员校验**——"仅管理员"是注释,不是强制门。
- **隧道 token 本身也是一个合法的应用层凭证**(映射到最小 `tunnel` 角色),且演示 token(`researcher-tok`、`alice-tok` 等)在真实模式下被 seed。生产环境应使用私有的、运维自行下发的凭证。
- 权限元数据表与数据同平面,仅靠"禁写"保护;**加权限请在服务器本地会话执行**。
- **无行级安全/列掩码**(不重写查询),也没有会话吊销/过期机制。
- 生产使用需补:每用户独立 ticket、`audit_table` 审计、自建 iroh relay,并在把本服务当作信任边界前完成上述强制机制的修复。

## 目录结构

```
server/
  server.py          # 服务端:RBAC + quack hooks + quackhole,支持 --sample / --db
  rbac_sample.lua    # 演示策略(protected = secret_data / public_data + RBAC 元数据);真实模式复制并编辑清单
client/
  client.py          # 客户端:attach + per-user 换 token + 查询/验证矩阵
test/
  test_rbac_lua.py   # lua 策略引擎单元回归(23 测例,无需网络)
```

## License

MIT(本仓库为集成示例;quackhole/iroh MIT,quack DuckDB 官方,duckdb-luajit MIT)。见 [LICENSE](LICENSE)。
