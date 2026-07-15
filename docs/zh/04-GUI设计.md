# 设计文档 04：GUI 设计 —— Founder Cockpit 与可验证控制面板

> 界面设计 · 2026-07
>
> 结论：GUI 必须有，而且不是锦上添花，而是决定项目能不能真正走出开发者圈的关键。底层架构很复杂（多模型、权限、沙箱、密钥、节点、审计、法务、税务、Agent 编排），**前端必须把这些复杂度隐藏起来，只在用户需要决策时才展开。**

## GUI 的核心原则

### 1. 用户管理的是"公司"，不是 Agent

首页不要出现：temperature、token、prompt、tool schema、Agent graph、embedding model、MCP configuration。

用户首页只需要看懂：

- 公司现在是什么状态
- 今天最重要的任务
- AI 正在做什么
- 哪些事情需要自己批准
- 当前有哪些风险
- 系统是否安全

Crew Orchestrator 在内部自动完成组队，高级用户再进入开发者模式查看。

### 2. 默认简单，逐层展开（三种界面深度）

#### Simple Mode —— 面向完全不懂技术的小白

只显示：下一步做什么、AI 已准备了什么、需要批准什么、有什么风险、本月收入/支出/任务。

#### Advanced Mode —— 面向独立开发者和专业创业者

增加：Agent 执行计划、模型选择、数据披露范围、工作流、自动化规则、权限配置、成本与质量指标。

#### Security Mode —— 面向安全研究人员和管理员

显示：节点状态、Capability Token、审计事件、密钥状态、数据复制、故障切换、Prompt Injection 告警、插件权限、网络活动。

**三种模式使用同一套数据，只是展示层级不同。**

---

## 主导航（最多七个一级入口）

```text
Home
Company
Work
Customers
Finance
Compliance
Security
```

避免左侧栏出现二三十个模块。

---

## 一、Home：Founder Command Center

用户每天打开的首页。建议布局：

```text
┌──────────────────────────────────────────────────────┐
│ Good morning, Founder                 System: Healthy │
│ Your business has 3 priorities today                 │
├───────────────────────────┬──────────────────────────┤
│ Today                     │ Needs your approval      │
│                           │                          │
│ 1. Review client proposal │ • Send proposal to Alex │
│ 2. Validate pricing       │ • Approve contract edit │
│ 3. Fix security warning   │ • Confirm tax category  │
├───────────────────────────┼──────────────────────────┤
│ Business pulse            │ AI Crew activity         │
│ Revenue      $8,200       │ Researcher: completed   │
│ Expenses     $2,100       │ Legal reviewer: working │
│ Runway       11 months    │ Security guard: blocked │
├───────────────────────────┴──────────────────────────┤
│ Biggest current risk                               │
│ You have not validated whether customers will pay. │
│ [Start validation experiment]                      │
└──────────────────────────────────────────────────────┘
```

首页最重要的是：

> 让用户在十秒内知道公司是否正常，以及自己现在应该做什么。

---

## 二、Company：企业数字孪生

展示公司的完整状态，但不要直接用 "Enterprise Digital Twin" 吓到小白。前端可以叫 **My Company**。

卡片式展示：

```text
Company
├── Identity
├── Products
├── Customers
├── Contracts
├── Assets
├── Obligations
└── Business assumptions
```

用户修改一项内容时，系统提示：

> 这项修改会影响你的合同模板、税务判断和营销定位。

让用户直观看到企业状态之间的关联。

---

## 三、Work：AI Crew 工作中心

不是展示一群拟人头像互相聊天，而是展示真实任务。

每个工作任务显示：

```text
Prepare proposal for Acme Ltd.

Status: Waiting for approval
Progress: 4 / 5 steps completed

✓ Customer context reviewed
✓ Pricing recommendation generated
✓ Proposal drafted
✓ Legal risk checked
○ Send proposal

AI Crew:
Research · Sales · Legal · Security

[Review output] [Approve next step]
```

### Crew View 可以提供，但不是默认页面

高级模式可以查看：

```text
Planner
   ↓
Research Agent
   ↓
Proposal Builder
   ↓
Legal Reviewer
   ↓
Policy Guard
   ↓
Human Approval
   ↓
Email Executor
```

每个节点显示：输入、输出、使用的模型、使用的数据、使用的权限、成本、是否通过校验。

---

## 四、Customers：客户和销售流程

小白最需要的是非常直观的客户漏斗：

```text
Leads → Contacted → Meeting → Proposal → Won
```

点击某个客户后显示：客户背景、最近互动、当前需求、AI 建议的下一步、合同、报价、发票、风险、数据授权范围。

例如：

> 建议下一步：发送一封跟进邮件。
> 原因：距离上次会议已经过去 6 天。
> AI 可以生成草稿，但不会未经批准直接发送。

---

## 五、Finance：财务与税务

必须做得像普通财务看板，而不是专业会计系统。

默认显示：收入、支出、利润、现金余额、税务预留、待付款项、待收款项、预计跑道。

税务区域只显示用户最关心的结果：

```text
Estimated tax reserve: SGD 4,200

Why?
• Estimated taxable profit: SGD 24,000
• Current assumptions: Singapore company
• 3 transactions need confirmation

[Review calculation]
```

点击后再展开：使用的规则、数据来源、汇率、假设、不确定项目、是否需要会计师确认。

---

## 六、Compliance：法务与合规中心

不要把它设计成"问 AI 律师"，更适合做成 **Compliance Inbox** —— 系统主动发现问题：

```text
High priority
Your client contract has no liability cap.

Medium priority
Your privacy policy may not cover EU customers.

Upcoming
Annual filing due in 42 days.
```

每个问题都有：发生了什么、为什么重要、涉及哪个司法辖区、建议做什么、AI 能做哪些、是否需要专业人士、依据来源和更新时间。

法务聊天可以存在，但应作为辅助入口，不是主入口。

---

## 七、Security：安全状态中心

对普通用户必须足够直观：

```text
Security Score: 87 / 100
Status: Protected
```

下方只显示几类信息：数据是否已加密、是否完成备份、是否存在异常登录、是否有插件越权、模型是否尝试访问敏感数据、是否有节点失效、最近是否成功完成恢复测试。

例如：

```text
Blocked threat

A document attempted to instruct the AI to upload your
customer database to an external website.

Result: Blocked
Data exposed: None
Action required: No
```

高级模式再展示完整事件链和策略决策。

---

## 八、全局 Approval Center

审批是整个产品最重要的交互之一。右上角始终有一个清晰入口：`Approvals 3`。

审批卡必须用自然语言解释：

```text
Send proposal to Acme Ltd?

The AI wants to:
• Send one email
• Attach Proposal-v3.pdf
• Share customer name and project requirements

It cannot:
• Access other customers
• Send additional emails
• Modify the proposal after approval

Permission expires in 5 minutes.

[Reject] [Edit] [Approve once]
```

这比显示 OAuth scope 或 JSON 权限更适合小白。

---

## 九、全局隐私指示器

每个 AI 任务旁边显示数据使用情况：

```text
Privacy: Local only
```

或：

```text
Privacy: Cloud-assisted
2 anonymized fields will be shared
```

用户点击后可以看到：发送给谁、发送什么、为什么、是否保存、使用哪个模型、是否能够切换为本地运行。

颜色和图标只作辅助，不能只依赖颜色表达风险。

---

## 十、节点和故障切换界面

普通用户只需要看到：

```text
System resilience

Primary model       Healthy
Backup model        Ready
Local model         Ready
Main device         Online
Recovery node       Synced 2 minutes ago
Encrypted backup    Verified today
```

故障发生时：

```text
Primary AI provider is unavailable.

Your work has automatically continued using Backup Provider B.
No data was lost.
Expected quality: Normal
```

进入高级界面后，再展示完整 Mesh：

```text
Desktop Node
    ↕
Encrypted NAS Replica
    ↕
Blind Cloud Backup

Model A → Model B → Local Model
```

---

## 十一、引导式创建公司（五步向导）

第一次启动不能让用户面对空白页面。

### Step 1：你想做什么？

```text
• Consulting service
• Micro-SaaS
• Digital product
• Freelance business
• I am not sure yet
```

### Step 2：你的基本情况

所在国家或地区、公司是否已注册、技能、可投入时间、可投入预算。

### Step 3：隐私偏好

```text
Maximum privacy —— Mostly local, slower
Balanced —— Local data protection with approved cloud models
Performance —— Use stronger cloud models when needed
```

### Step 4：连接工具（全部可跳过）

邮箱、日历、GitHub、文件、财务系统。每个连接都明确解释权限。

### Step 5：生成第一份行动计划

最终直接进入：

> 你的公司当前处于"问题验证阶段"。
> 今天建议先完成三项任务。

---

## 十二、命令栏和对话入口

聊天仍然有必要，但不要让整个产品只有聊天。

底部提供一个全局命令栏：

```text
Ask or tell Sovereign what you want to achieve...
```

用户可以输入：

- 帮我准备这个客户的报价
- 我是否需要注册 GST
- 检查这份合同
- 为什么今天暂停了这个 Agent
- 如果 OpenAI 失效会发生什么
- 帮我备份全部公司数据
- 显示这个月的现金流风险

系统把自然语言命令映射到真实对象和工作流。

---

## 十三、技术实现建议

```text
Tauri
React
TypeScript
Rust secure core
```

Tauri 比 Electron 更适合这个定位：安装包较小、与 Rust 安全内核结合自然、本地文件和系统能力可控、更适合 local-first 桌面应用、支持 macOS/Windows/Linux。

前端状态管理保持简单：

- React Query：服务端和本地 Runtime 状态
- Zustand：界面状态
- JSON Schema：动态表单
- WebSocket 或本地 IPC：实时工作流状态

**第一版优先做桌面端**，因为隐私和本地运行理念在纯网页端很难完整兑现。

---

## 十四、Demo 与完整版的 GUI 关系

不要分别开发两个前端。同一个 GUI 通过 Profile 控制功能。

### Playground Profile

使用虚拟公司、固定示例工作流、展示模型切换、展示恶意插件阻断、展示节点恢复、不连接真实资产。

### Community Profile

真实本地数据、本地 Vault、多模型、本地模型、MCP、基础 Founder OS、完整数据导出。

### High-Assurance Profile

增加：多节点、多人审批、HSM、SIEM、企业身份、高级审计。

所有 Profile 使用相同组件和设计语言。

---

## 十五、最先应该完成的 GUI 页面

第一阶段只做六个页面：

1. **Onboarding**
2. **Founder Home**
3. **Work Detail**
4. **Approval Center**
5. **Security Center**
6. **Settings / Models / Backup**

客户、财务、法务等复杂页面可以先以卡片和任务形式进入 Work Detail。

第一版 UI 的完整闭环：

```text
创建虚拟公司
→ 输入经营目标
→ AI 生成工作计划
→ 查看 Crew 执行
→ 模型发生故障并切换
→ 恶意操作被阻止
→ 用户审批安全动作
→ 查看审计记录
```

---

## 最终判断

项目必须同时具备两种界面：

> **面向普通用户的 Founder Cockpit** 和 **面向开发者、安全研究者的可验证控制面板**

默认界面应该像一个清晰的企业管理工具，而不是 AI 实验室；复杂架构只在用户需要理解、审批、调试或审计时才逐层展开。

最重要的 GUI 设计原则：

> **系统内部可以非常复杂，但用户每个时刻只需要做一个清楚的决定。**
