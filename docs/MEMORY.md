# 启动期内存占用说明与优化

## 现象

程序启动时内存一度达到约 **700MB**，随后回落到 **15MB** 左右。这是预期内的行为，不是泄漏。

## 原因分析

### 1. 调试构建 (cargo run / debug)

- **opt-level=0** 时代码几乎不优化，分配多、内联少，栈与堆都偏大。
- 依赖库（tokio、hyper、rustls、hickory-resolver、ssh2/OpenSSL）在首次初始化时会有一次性分配。
- 这些内存在初始化完成后会被释放，但系统分配器不一定立刻把空闲内存归还给 OS，所以会先看到一次峰值，再慢慢回落。

### 2. 主要依赖的一次性开销

| 组件 | 可能贡献 | 说明 |
|------|----------|------|
| **ssh2**（含 OpenSSL/libssh2） | 较大 | 首次使用前会加载加解密与证书相关结构，尤其 OpenSSL 的全局初始化。 |
| **rustls / tokio-rustls** | 中等 | 若启用 TLS，加载证书、根证书链会带来一次性分配。 |
| **hickory-resolver** | 中等 | 创建解析器、加载系统 DNS 配置与缓存时会有分配。 |
| **tokio** (rt-multi-thread) | 中等 | 工作线程、任务队列等运行时结构在启动时建立。 |
| **系统分配器** | - | 默认分配器在 Windows 上会保留已释放的块，RSS 回落可能滞后。 |

启动阶段这些初始化叠加，容易在 **debug** 下出现数百 MB 的峰值；之后请求处理进入稳定状态，只保留常驻结构，因此会回落到约 15MB。

### 3. 为何会“先高后低”

- 启动时：配置解析、DNS 初始化、TLS 加载（若开启）、tokio 运行时等一次性完成。
- 之后：大块临时缓冲和初始化结构被 drop，内存还给分配器。
- 分配器可能先保留这些空闲内存供后续复用，过一段时间或在高内存压力下再归还 OS，因此你会先看到 700MB，再看到 15MB 左右的稳定值。

## 优化建议

### 1. 开发时降低峰值（已做）

在 `Cargo.toml` 中为 dev 开启适度优化：

```toml
[profile.dev]
opt-level = 1
```

这样仍能较快编译，但比纯 debug 少很多分配和栈占用，启动期内存峰值通常会明显下降（例如从 700MB 降到 200MB 量级，视环境而定）。

### 2. 生产使用 release 构建

```bash
cargo build --release
./target/release/p-proxy.exe
```

release 下会做 LTO、strip 等，分配和代码体积都更小，**常驻内存和启动峰值都会低很多**（通常就在十几 MB 量级），建议生产环境始终用 release。

### 3. 可选：更换全局分配器

若希望峰值更早、更稳定地回落，可尝试使用 **mimalloc**（跨平台、对峰值和碎片较友好）：

```toml
# Cargo.toml
[dependencies]
mimalloc = { version = "0.1", optional = true }
```

```rust
// main.rs 顶部
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
```

然后以 `cargo run --release --features mimalloc` 运行并观察内存。是否启用可按需要决定。

### 4. 可选：延迟初始化 DNS

若配置里经常不配 `dns_domains`，可以改为在**首次需要 DNS 解析时**再创建 `DnsManager`，从而减少“空配置”下的启动分配。当前实现是启动时若配置了 DNS 就创建，对多数场景已经足够。

## 小结

- **700MB → 15MB** 是“启动一次性初始化 + 分配器未立刻还 OS”的典型表现，不是泄漏。
- **开发**：已通过 `[profile.dev] opt-level = 1` 降低峰值；日常用 `cargo run` 即可。
- **生产**：务必使用 `cargo build --release`，内存和性能都会明显更好。
- 若仍对峰值敏感，可再尝试 `mimalloc` 或按需做 DNS 延迟初始化。
