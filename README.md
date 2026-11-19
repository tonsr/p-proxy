# p-proxy

**它不是代理工具。它的核心任务是把互相隔离的内网连起来，代理只是它可用的一种武器。**

一个用 Rust 写的单入口网络汇聚网关：一个端口同时提供 HTTP / HTTPS CONNECT / SOCKS5 / WebSocket 四种接入方式，
按「目标地址 + 端口」白名单把流量自动分发到不同的上游跳板（HTTP 代理、SOCKS5 代理、ws/wss 隧道），
并把数据库、SSH、Git 这类 TCP 服务以隧道方式挂在同一条规则上。

客户端永远只配一个地址，不再维护一长串节点来回切换。

---

## 能力一览

| 能力 | 说明 |
| --- | --- |
| 多协议单入口 | HTTP 正向代理、HTTPS CONNECT、SOCKS5、WebSocket 隧道，一个端口共存 |
| 目标级白名单路由 | `domains` 支持 `域名` / `*.通配` / `IP` / `CIDR` / `host:port` |
| 三种上游 | `HTTP host:port`、`SOCKS5 host:port`（无认证上游）、`ws://` / `wss://` 隧道（`{domain}` 模板替换） |
| 规则绑定 TCP 隧道 | 规则里声明的 `type: tcp` 端点在本地监听，流量经**这条规则的上游**转发到目标 |
| WebSSH | `type: ssh` 端点可在 Web UI 里直接开终端，密码在页面输入，不落配置 |
| WS 服务端 | 自带 `/ws?token=...&proxy=host:port` 端点，供其他节点/终端接入，可多级级联 |
| 网关自连 | 本机的 `ws_proxy` 与本机的 wss 上游规则可以互连，用于本地闭环调试 |
| DNS 分组回退 | 域名未命中规则时按 `dns_domains` 分组解析，拿到 IP 后再匹配一次规则 |
| 直连白名单 | `allow_direct_access` + `direct_access_white_list`，未命中规则的流量按白名单决定放不放行 |
| 用户与出口绑定 | 每个用户用 `auth_rules` 限定只能使用哪些规则，`is_admin` 放行全部 |
| WSS ECH | `wss-ech` 支持加密客户端问候，便于在受限网络里连自建 wss 节点 |
| Web UI | 基本配置 / 规则 / DNS / 用户 / 隧道 / 统计 / 日志 / 命中检查，改完即时生效 |

release 构建下常驻内存十几 MB 量级；启动期内存峰值属于一次性初始化，不是泄漏，见 `docs/MEMORY.md`。

---

## 预编译包

[Releases](https://github.com/tonsr/p-proxy/releases) 页面按平台提供打包好的二进制，解压即用。每个包里含二进制、`README.md`、`LICENSE`、`config.example.yaml`。

| 平台 | 目标三元组 | 说明 |
| --- | --- | --- |
| Linux x86_64 | `x86_64-unknown-linux-gnu` | glibc，主流发行版 / 容器 |
| Linux aarch64 | `aarch64-unknown-linux-gnu` | 树莓派 4/5、ARM 服务器、香橙派 |
| Linux armv7 | `armv7-unknown-linux-gnueabihf` | 树莓派 2/3、老式 ARM 盒子和路由器 |
| macOS Apple Silicon | `aarch64-apple-darwin` | M 系列 |
| macOS Intel | `x86_64-apple-darwin` | Intel Mac |
| Windows x86_64 | `x86_64-pc-windows-gnu` | 免安装 exe（已静态链接 OpenSSL） |
| Android arm64 | `aarch64-linux-android` | Termux 里直接跑，见下方说明 |
| Android arm | `armv7-linux-androideabi` | 32 位 Android / 老盒子 |

Linux 的 ARM 包是在 CI 里为目标架构现编 OpenSSL / zlib 的静态版本，不依赖目标机装 `libssl-dev`。

**Android 包不含 WebSSH**：`ssh2 → libssh2 → OpenSSL` 在 NDK 下交叉编译代价太大，因此 Android 版用 `--no-default-features` 构建。代理、规则分流、TCP 隧道、Web UI、WSS 出口全部保留，只有 WebSSH 终端页不可用（访问会返回 501）。手机上通常也有更顺手的 SSH 客户端。

```bash
# 以 Termux（arm64）为例
tar -xzf p-proxy-android-arm64.tar.gz
cd p-proxy-android-arm64
cp config.example.yaml config.yaml
./p-proxy
```

Android 版要在 Termux 里跑，先 `pkg install tsu` 或直接用 `termux-wake-lock` 防止休眠杀进程；监听 1024 以下端口需要 root。

```bash
# Lime / OpenWrt 类设备请用对应的 Linux 包，不要用 Android 包
```

```bash
# 以 aarch64 为例
tar -xzf p-proxy-aarch64-unknown-linux-gnu.tar.gz
cd p-proxy-aarch64-unknown-linux-gnu
cp config.example.yaml config.yaml
./p-proxy
```

> 二进制只有一份，做服务端还是客户端由 `rules` 里每条规则的 `target` 决定，不需要区分版本。

---

## 快速开始

```powershell
cd F:\git\p-proxy
Copy-Item config.example.yaml config.yaml   # 按需改
cargo run --release
```

默认监听 `proxy_server.bind_address:proxy_server.bind_port`（示例为 `0.0.0.0:51080`）。

客户端配置（任选其一，都指向同一个地址）：

```powershell
# HTTP / HTTPS
$env:HTTP_PROXY  = "http://127.0.0.1:51080"
$env:HTTPS_PROXY = "http://127.0.0.1:51080"

# SOCKS5
curl.exe --socks5-hostname 127.0.0.1:51080 http://10.20.30.40/
```

---

## 配置结构

```yaml
version: '202603161336'          # 带日期版本号；ws-proxy 同协议节点用 version 判断走底层流 relay
proxy_server:
  http_proxy_enable: true
  https_proxy_enable: true        # HTTPS CONNECT
  socks5_proxy_enable: true
  no_tls_enable: true             # bind_port 上开明文监听
  bind_address: 0.0.0.0
  bind_port: 51080

  ws_proxy:                       # WS 接入端点（服务端）
    enable: true
    path: /ws
    token: 'change-me'
    rate_limit_per_minute: 10     # 按客户端 IP；0 不限制，超限 429

  web_ui:
    enable: true
    path: /ui

  tls_enable: false               # TLS 只服务 /ui 与 /ws，不影响代理端口
  tls_cert_file: null
  tls_key_file: null
  tls_bind_port: null             # 默认 bind_port + 1

  allow_anonymous: true
  allow_direct_access: true
  direct_access_white_list: []

  log:
    enable: false
    level: info
    path: ./proxy.log
    encoding: json

  users:
    - name: admin
      password: admin
      auth_rules: 'prod,office'   # 逗号分隔，限定可用的 rules[].name
      is_admin: true

  dns_domains:
    - name: intranet
      domains: '*.corp.internal,*.corp.local'
      servers:
        - 10.20.0.53:53

  rules: ...                      # 见下方案例
```

`rules[]` 每一项：

```yaml
- name: <唯一名>
  target: HTTP 10.20.0.10:8080        # 或 SOCKS5 10.20.0.10:1080
                                      # 或 wss://gw.example.net/ws?token=xxx&proxy={domain}
  domains: >                          # 逗号或换行分隔
    *.corp.internal,
    10.20.30.0/24,
    10.20.30.41:5432
  headers:                            # 仅 ws/wss 上游使用
    - 'Host: gw.example.net'
    - 'Accept: */*'
  wss-ech:                            # 可选，仅 wss://
    enable: false
    inner_hostname: gw.example.net
    connect_host: null
    ech_config_file: null
    ech_doh_lookup: false
    ech_doh_cloudflare: false
  websocket-tunnel:                   # 可选，规则绑定的隧道端点
    - tunnel_name: pg-tunnel
      name: 生产库
      target: 10.21.5.6:5432
      type: tcp                       # ssh = WebSSH；tcp = 本地监听转发
      bind_address: 127.0.0.1:15432
      user: null
```

---

## 使用案例

### 案例 1：一个入口打通多套隔离内网

**痛点**：办公区、生产网、测试网、机房各有一套跳板，客户端里存一堆 PROXY / SOCKS5 节点，每次换环境手动切，切错就不通。

**做法**：客户端只留 `127.0.0.1:51080`，切换工作交给网关的规则表。

```yaml
proxy_server:
  bind_address: 0.0.0.0
  bind_port: 51080

  rules:
    - name: office                      # 办公区，走前置 SOCKS5
      target: SOCKS5 10.20.0.10:1080
      domains: 10.20.0.0/24, *.corp.internal

    - name: prod                        # 生产网，走前置 HTTP 代理
      target: HTTP 10.20.0.20:8080
      domains: 10.21.0.0/24, 10.22.5.6:8443

    - name: remote                      # 远端机房，走自建 wss 隧道节点
      target: wss://gw.example.net/ws?token=CHANGE_ME&proxy={domain}
      domains: 172.18.0.0/16, *.farm.internal
```

客户端 `HTTP_PROXY` / `HTTPS_PROXY` / `--socks5-hostname` 全部指向 `127.0.0.1:51080`。之后换环境只是改网关 YAML，或者在 `/ui/rules` 页面上改，终端不用动。

> `{domain}` 会被替换成实际的 `host:port`，拼进上游 WS 端点的 `proxy` 查询参数。

---

### 案例 2：同一台机器不同端口走不同跳板

生产环境里同一个 IP 上，22 端口只对运维网开放、5432 只对数据网开放、443 只对业务网开放。用 `host:port` 精确匹配，不用把一条 IP 拆成多条网段规则。

```yaml
rules:
  - name: prod-ssh
    target: SOCKS5 10.20.0.10:1080
    domains: 10.21.5.6:22

  - name: prod-db
    target: HTTP 10.20.0.20:8080
    domains: 10.21.5.6:5432

  - name: prod-web
    target: SOCKS5 10.20.0.30:1080
    domains: 10.21.5.6:443

  - name: prod-any                 # 兜底：这台机器其它端口统一走一个出口
    target: HTTP 10.20.0.20:8080
    domains: 10.21.5.6
```

`10.21.5.6:22` 这种写法对域名、IP 都成立（例如 `git.corp.internal:30022`）。
注意这里的端口是**客户端实际要连的端口**，不是网关自己的监听端口。

---

### 案例 3：内网域名 + DNS 回退 + 直连白名单

内网域名在系统 DNS 里查不到，需要网关按分组解析，解析出的 IP 再进一次规则匹配。

```yaml
proxy_server:
  dns_domains:
    - name: corp
      domains: '*.corp.internal,*.corp.local'
      servers:
        - 10.20.0.53:53
    - name: farm
      domains: '*.farm.internal'
      servers:
        - 10.31.0.53:53

  allow_direct_access: true
  direct_access_white_list:
    - 10.20.0.0/24                       # 整段，任意端口可直连
    - 192.168.50.7:8443                  # 单 IP 单端口
    - 10.21.0.0/24:[80,443,30000-39999]  # 指定端口 + 端口范围
```

判定顺序：`host` 直接命中规则 → 用 `dns_domains` 解析 → 拿 IP 再命中规则 → 仍未命中则按 `allow_direct_access` + 白名单决定直连还是拒绝。

`allow_direct_access: false` 就是「白名单之外一律不出网」，适合和堡垒机、审计策略对齐。

---

### 案例 4：把数据库 / Git SSH 挂成规则绑定的 TCP 隧道

不用再额外维护 `ssh -L`、frp。隧道端点写在规则里，**流量走这条规则自己的上游 target**。

```yaml
rules:
  - name: prod-db
    target: HTTP 10.20.0.20:8080
    domains: 10.21.5.6:5432
    websocket-tunnel:
      - tunnel_name: pg-tunnel
        name: 生产库
        type: tcp
        target: 10.21.5.6:5432
        bind_address: 127.0.0.1:15432      # 只给本机用，别写成 0.0.0.0

  - name: prod-git
    target: SOCKS5 10.20.0.10:1080
    domains: git.corp.internal:30022
    websocket-tunnel:
      - tunnel_name: git-tunnel
        name: 代码提交
        type: tcp
        target: git.corp.internal:30022
        bind_address: 127.0.0.1:30022
```

用法：

```powershell
psql "host=127.0.0.1 port=15432 dbname=app user=app"

# Git over SSH
$env:GIT_SSH_COMMAND = "ssh -p 30022 -o StrictHostKeyChecking=accept-new"
git clone ssh://git@127.0.0.1:30022/app/repo.git
```

要点：

- 隧道不绕开路由，仍然按 `target` 指定的上游转发，「哪条规则能到哪」和「隧道能到哪」是同一套权限；
- 上游建连超时 60 秒；
- `bind_address` 一旦写成 `0.0.0.0`，等于把内网服务直接摊给所有能访问这台机器的人，而且**不经过代理鉴权**。

---

### 案例 5：浏览器里直接开 SSH（WebSSH）

`type: ssh` 的端点不占本地端口，而是由 Web UI 提供终端页。

```yaml
rules:
  - name: prod-ssh
    target: SOCKS5 10.20.0.10:1080
    domains: 10.21.5.6:22
    websocket-tunnel:
      - tunnel_name: ssh-box
        name: 生产服务器
        type: ssh
        target: 10.21.5.6:22
        user: ops
```

打开 `http://127.0.0.1:51080/ui/tunnels`，点「WebSSH」进 `/ui/webssh/<rule>/<tunnel_name>`。
密码在页面里输入，不写进配置文件；`/ui/webssh-files/...` 是文件列表入口（SFTP 通道建设中）。

---

### 案例 6：两台网关级联（只有出站，不开入站端口）

A 在一个隔离网里，B 在另一侧。B 只允许出站 443，边界不放任何入站端口：

- A：开 `/ws` 端点，作为接入侧；
- B：规则 target 指向 A 的 wss 端点，B 主动连 A；
- B 侧再开自己的 `/ws`，供更下游的 C 接入。

A 侧：

```yaml
version: '202603161336'
proxy_server:
  ws_proxy:
    enable: true
    path: /ws
    token: 'edge-token'
    rate_limit_per_minute: 20
  tls_enable: true
  tls_cert_file: ./certs/site.crt
  tls_key_file: ./certs/site.key
  tls_bind_port: 443
  web_ui:
    enable: false
```

B 侧：

```yaml
proxy_server:
  rules:
    - name: to-a
      target: wss://gw-a.example.net/ws?token=edge-token&proxy={domain}
      headers:
        - 'Host: gw-a.example.net'
      domains: 10.21.0.0/24
```

链路：`终端 → B(51080) → 规则命中 → 出站 wss → A 的 /ws → A 再按自己的规则走`。
两边 `version` 一致时走底层流 relay，链路更短。`ws_proxy.token` 是接入校验，和 `users` 的账号密码是两套体系。

自连调试：把 B 的 target 写成本机 `wss://127.0.0.1:443/ws?...`，再用 `curl` 从 51080 打一条内网地址，可以完整验证「接入 → 匹配 → 隧道 → 回程」这一整圈。

---

### 案例 7：不同人只能走各自的出口

```yaml
users:
  - name: dev
    password: dev-pass
    auth_rules: 'office,prod-ssh'
    is_admin: false

  - name: dba
    password: dba-pass
    auth_rules: 'prod-db'
    is_admin: false

  - name: admin
    password: '换成强口令'
    is_admin: true            # 放行全部规则
```

- HTTP/HTTPS：`Proxy-Authorization: Basic base64(user:pass)`
- SOCKS5：`allow_anonymous: false` 时要求用户名密码
- 命中不在 `auth_rules` 里的规则 → 拒绝

Web UI 登录用第一个 `is_admin: true` 的账号。

---

### 案例 8：TLS 只保护 Web UI 和 WS 入口

```yaml
proxy_server:
  no_tls_enable: true         # 51080 继续明文，给本机客户端用
  tls_enable: true
  tls_bind_port: 51081
  tls_cert_file: ./certs/site.crt
  tls_key_file: ./certs/site.key
```

TLS 监听端口只服务 `web_ui.path` 与 `ws_proxy.path`，代理端口行为不变。适合「内网明文 + 对外只开加密入口」的部署方式。

---

## 规则匹配的准确语义

- **`rules` 是选路器，不是权限边界**：它只决定「这个目标走不走这条上游」，不做授权。真正的访问控制在上游（带 ACL 的网关/网闸）或 `users.auth_rules`。所以 `target` 是**裸 SOCKS5 / HTTP 代理**（上游不做任何限制）时，`domains` 的粒度就是实际边界，`host:0` 等于该主机的全部端口放行；`target` 是带 ACL 的上游时，`domains` 可以放宽，细分交给上游。
- **优先级 = `rules` 数组顺序**，命中多条时取**下标最小**的那条，不是「写得越精确越优先」。想让精确匹配优先，就把 `host:port` 规则放在网段规则前面。
- 同一个 host 同时命中「域名本身」和「host:port」时，同样按下标最小决定。
- `domains` 分隔符是逗号或换行（分号不是分隔符，写了会被当成字面量）。
- 支持写法：`*.example.com`（含 apex）、`+*.example.com`、`example.com`、`1.2.3.4`、`1.2.3.0/24`、`1.2.3.4:8080`、`name:port`。IPv4 参与匹配，IPv6 目前不参与。
- **`domains` 的端口只支持单个数字**：`host:8080` 有效，`host:0` 表示该 host 的**任意端口**。`host:[80,443]`、`host:30000-39999` 这类端口集/区间写法**不支持**，且会被当成域名精确匹配而静默失效（不报错、不命中）。端口集语法只存在于 `direct_access_white_list`。
- 转发到上游或直连时会剥离 hop-by-hop 头（`Connection`、`Proxy-Authorization`、`Transfer-Encoding` 等）。
- wss 上游**跳过服务端证书校验**（方便连自签名内网节点）；URL 里是 IP、又配了 `Host` 头时，会用 `Host` 的主机名替换连接地址，便于 SNI 与 CDN 路由；`Sec-WebSocket-Key` / `Sec-WebSocket-Version` 不会被 headers 覆盖。
- 上游 SOCKS5 只支持无认证；HTTP 上游支持普通请求与 CONNECT。

---

## Web UI

`web_ui.enable: true` 后访问 `/ui`（Basic Auth，admin 账号）：

| 路径 | 用途 |
| --- | --- |
| `/ui` | 基本配置（监听、WS、UI、日志等），保存即时生效 |
| `/ui/rules` | 规则增删改，立即生效 |
| `/ui/dns` | DNS 分组 |
| `/ui/users` | 用户与 `auth_rules` |
| `/ui/tunnels` | 隧道端点列表、WebSSH 入口 |
| `/ui/stats` | 按用户统计当天请求量（UTC，内存计数） |
| `/ui/logs` | 最近日志（读 `log.path`） |
| `/ui/check?host=10.21.5.6:5432` | 查某个 host 命中哪条规则；未命中会走 DNS 回退，并对 HTTP 上游做一次 TCP 连通性检测 |

排障先看 `/ui/check`，比抓包快。

---

## 安全须知

按风险从高到低：

1. **隧道 `bind_address` 不要写 `0.0.0.0`**。那等于绕过代理鉴权把内网端口摊出去，还可能占用 443 / 5432 / 22 这类标准端口。
2. **`allow_anonymous: true` + `bind_address: 0.0.0.0`**：任何人不用认证就能接进来。只在可信内网开匿名。
3. **默认口令**：`admin/admin`、示例里的 token，上线前全部换掉。
4. **`tls_enable: false`**：代理端口、UI、WS 全明文，账号和 token 可被抓包。跨不可信链路必须开 TLS，或者放进隧道。
5. **`log.enable: false`**：没有审计记录，出事无法溯源。
6. **wss 上游不校验证书**：等同于接受中间人，只用于你信任的自签名内网节点。

---

## 构建 / 交叉编译 / Docker

```powershell
cargo build --release          # 产物 target/release/p-proxy(.exe)
```

`Cargo.toml` 里 `[profile.dev] opt-level = 1` 是为了压低 debug 启动期内存峰值，生产请始终用 release。

交叉编译 aarch64 Linux 需要目标平台 C 工具链（`rustls` 的 `aws-lc-rs` 后端要编译 C 代码）：

```powershell
cargo install cross
cross build --release --target aarch64-unknown-linux-gnu
```

或在 WSL / Linux 上 `sudo apt install gcc-aarch64-linux-gnu` 后直接 `cargo build --release --target aarch64-unknown-linux-gnu`。

Linux 的 ARM 目标需要注意：`ssh2` 会通过 CMake 构建 libssh2，而 cross 的交叉工具链把 CMake 的库搜索限制在 sysroot 内。仓库里的 `Cross.toml` 已处理这点——在 pre-build 里为目标架构现编 OpenSSL / zlib 并装进 sysroot。一半时间都花在这两个 C 库上。

目标平台没有可用 OpenSSL 时（例如 Android/NDK），直接去掉 WebSSH：

```powershell
cross build --release --target aarch64-linux-android --no-default-features
```

CI 的完整矩阵（`.github/workflows/release.yml`）：Linux x86_64 / aarch64 / armv7、macOS Intel / Apple Silicon、Windows x86_64、Android arm64 / arm，打 `v*` tag 时自动汇总挂到 Release。

Docker（镜像内二进制名为 `p-proxy`）：

```powershell
docker build -t p-proxy .
docker run -d --name p-proxy -p 51080:51080 -v ${PWD}/config.yaml:/app/config.yaml:ro p-proxy
```

---

## 合规声明

本项目面向**企业内部互相隔离的网络之间按需连通、开发与运维跳板**这类场景。

- 仓库内示例一律使用私有地址与占位域名，**不提供任何境外节点、订阅或跨境访问配置**；
- 技术上它具备构建任意跨网链路的能力，但本项目不为此提供支持，也不接受把项目用于规避网络管理、跨境违规访问的用途；
- 使用者需自行遵守所在地法律法规与所属组织的网络管理规定，一切使用后果由使用者承担。

---

## License

[MIT](LICENSE)。可自由使用、修改、分发、商用，可闭源衍生，**无回贡义务**；允许借助 AI / 大模型 / 代码助手参与二次开发，产出的代码权利归你。
唯一要求：保留版权声明与许可声明。

Copyright (c) 2026 tonsr · [github.com/tonsr](https://github.com/tonsr) · ak48159@qq.com
