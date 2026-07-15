# 设计文档（中文）

本目录包含 Sovereign Founder OS 的**完整产品与工程设计规格**。所有设计意图均公开可查，是项目的权威蓝图。

> **用 AI 建立和经营属于你自己的一人公司，同时不放弃对数据、决策和企业的控制权。**

Sovereign Founder OS 是完整产品和唯一主品牌。普通用户使用 Venture Studio、AI Crew、Product & Delivery、Customers & Growth、Finance / Legal / Tax 和 Founder Command Center；Sovereign Trust Layer 在底层提供主权、安全与韧性。

## 阅读顺序

建议按编号顺序阅读，文档之间存在演进关系：

```text
01 产品设想 → 02 主权升级 → 03 开源企划书 → 04 界面设计
```

| 文档 | 标题 | 核心内容 |
| --- | --- | --- |
| [01](01-AI-Founder-OS-初步设想.md) | AI Founder OS 初步设想 | 产品定位、Venture Graph、Founder Cockpit、临时 Crew、三层隐私区、L0–L3 自动化、五条初版工作流、技术路线、商业模式 |
| [02](02-Sovereign-Founder-OS-主权升级.md) | 主权型升级 | Enterprise Digital Twin、Jurisdiction Engine、税务引擎、企业免疫系统、密码学控制平面、PQC、分布式韧性、四阶段落地 |
| [03](03-开源项目企划书-v0.1.md) | 开源项目企划书 v0.1 | 完整产品结构、Sovereign Runtime、与 OpenClaw 差异化、六平面架构、SPOF 清单、插件安全、Chaos CLI、Stage 0–7、商业模式 |
| [04](04-GUI设计.md) | GUI 设计 | 三种界面深度、七个一级导航、Approval Center、隐私指示器、五步引导向导、首批六个页面 |

## 与英文文档的关系

| 类型 | 位置 | 用途 |
| --- | --- | --- |
| 英文概要 | 仓库根目录（`VISION.md`、`ARCHITECTURE.md` 等） | 国际开源社区快速了解 |
| 中文完整规格 | 本目录 `docs/zh/` | 全部设计细节与工程决策 |

英文文档是摘要和入口；**本目录是完整蓝图**。

## 关键设计决策速查

- **唯一产品主品牌**：Sovereign Founder OS 是帮助普通人创建和经营一人公司的完整产品；Runtime 是其底层技术基础
- **AI 编排**：AI Crew 是用户功能模块；Crew Orchestrator 是内部编排组件，不是第二主品牌
- **底层实现**：Sovereign Trust Layer 由 Sovereign Runtime 承载，包括 Model Mesh、Policy Engine、Secure Vault、Audit Ledger、Tool Sandbox 和 Recovery Mesh
- **开发顺序**：先完成 Trust Layer 的最小可信基础，再用真实 Founder OS 工作流验证；工程顺序不改变产品定位
- **核心抽象**：Sovereign Enterprise Graph（企业数字孪生），不是聊天记录
- **安全架构**：Mutually Constrained Autonomy（相互制约的自主性）
- **韧性目标**：Kill Everything 演示 —— 模型、服务器、插件全部失效，公司继续运转
- **数据分级**：Red（不出设备）/ Amber（脱敏后上云）/ Green（可上云）
- **技术栈**：Rust 安全内核 + TypeScript/React/Tauri + Python 隔离 Worker
- **许可证**：Apache 2.0（见根目录 [LICENSE](../../LICENSE)）
- **商标**：见 [TRADEMARK.md](../../TRADEMARK.md)

## 英文文档索引

完整文档地图见 [docs/INDEX.md](../INDEX.md)。
