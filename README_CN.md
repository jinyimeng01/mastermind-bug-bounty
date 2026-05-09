# Mastermind Bug Bounty — 自主化漏洞赏金编排系统

> 基于 trace37 的 **Mastermind Hooks Architecture** 构建的生产级 AI 技能系统，
> 将 6 个 Claude Code Hook 转化为可执行的工作流模式，赋予 Kimi 持久的狩猎记忆、分级审核、重试逻辑以及 HackerOne 级别的输出质量。

---

## 项目概览

本项目将 [trace37 labs](https://labs.trace37.com/blog/mastermind-hooks-architecture/) 的 6 个 Claude Code Hook 移植为模块化、开源的技能系统。它将通用 AI 转化为具备以下能力的自主漏洞赏金猎人：

- **会话连续性** — 随时中断、随时恢复，精确回到上次离开的位置
- **智能分级管控** — 对反模式发出软警告，对未经验证的发现执行硬拦截
- **自校正重试机制** — 检测过早放弃行为，自动注入绕过策略
- **取证级日志** — 每一次工具调用、每一个发现和每一项决策都有时间戳，支持审计追踪
- **状态交接** — 完整的狩猎序列化，支持长期任务的无缝衔接

---

## 架构设计

本技能系统实现了覆盖漏洞赏金全生命周期的 **6-Hook 架构**：

```
SESSION START          PRE-TOOL              TOOL              POST-TOOL
-------------          --------              ----              ---------

[上下文注入器]   →   [协调器守护]   →   [nuclei/sqlmap]  →   [工作日志记录器]
加载 ledger +         对同一主机的            执行                  记录结果 +
最近工作日志           >3 次请求发出          工具                  时间戳
注入会话               软警告或技能
上下文                 文件越权读取
                            |
                       [分级审核门]
                       置信度 < 0.7
                       或无影响证明时
                       执行硬拦截
                            |
                            ▼
                    [POST-TOOL 续]
                    [重试检测器]
                    对 "WAF 拦截" 等
                    结论进行模式匹配
                    按需注入绕过策略
                            |
                            ▼
                    ┌──────────────────────┐
                    │      交接保存器       │
                    │  会话结束时：         │
                    │  序列化目标 + 发现 +  │
                    │  代理状态到 Obsidian  │
                    │  知识库              │
                    └──────────────────────┘
```

### 六大 Hook 一览

| # | Hook | 类型 | 文件 | 职责 |
|---|------|------|------|------|
| 1 | **上下文注入器** | SESSION | `scripts/session_context.py` | 会话启动时注入狩猎状态 + 近 30 分钟工作日志 |
| 2 | **协调器守护** | PRE-TOOL (软) | `scripts/coordinator_guard.py` | 速率限制警告 + 强制专家代理委派 |
| 3 | **分级审核门** | PRE-TOOL (硬) | `scripts/triage_gate.py` | 拦截缺乏可证明影响的发现 |
| 4 | **工作日志记录器** | POST-TOOL | `scripts/worklog_recorder.py` | 每次操作双写 JSONL + Obsidian |
| 5 | **重试检测器** | POST-TOOL | `scripts/retry_detector.py` | 检测过早投降，建议绕过方案 |
| 6 | **交接保存器** | COMPACT | `scripts/handoff_saver.py` | 完整狩猎状态序列化，供下次会话加载 |

---

## 项目结构

```
mastermind-bug-bounty/
├── SKILL.md                          # 主技能定义（Kimi 工作流模式）
├── README.md                         # 英文文档
├── README_CN.md                      # 中文文档（本文件）
│
├── references/                       # 攻击面安全知识库
│   ├── hunt_methodology.md           # 完整方法论：侦察 → 发现 → 验证 → 报告
│   ├── bug_classes.md                # 10 大类现代漏洞及利用技术
│   ├── bypass_techniques.md          # WAF/CDN 指纹与绕过百科全书
│   └── report_templates.md           # HackerOne / Bugcrowd / CVE 提交模板
│
└── scripts/                          # 自动化工具（零外部依赖，纯标准库）
    ├── session_context.py            # Hook 1: 上下文注入
    ├── coordinator_guard.py          # Hook 2: 软管控
    ├── triage_gate.py                # Hook 3: 硬分级验证
    ├── worklog_recorder.py           # Hook 4: 双通道日志
    ├── retry_detector.py             # Hook 5: 过早投降检测
    └── handoff_saver.py              # Hook 6: 状态序列化
```

---

## 快速开始

### 环境要求

- Python 3.9+
- 零外部依赖（仅使用 Python 标准库）

### 安装

```bash
git clone https://github.com/yourusername/mastermind-bug-bounty.git
cd mastermind-bug-bounty
```

### 创建狩猎工作区

```bash
mkdir -p my-hunt/vault
python3 -c "
import json
json.dump({
    'hunt_id': 'hunt-001',
    'target': 'example.com',
    'scope': ['*.example.com'],
    'status': 'active',
    'start_date': '2026-05-09T00:00:00Z'
}, open('my-hunt/ledger.json', 'w'), indent=2)
"
touch my-hunt/worklog.jsonl
```

### 脚本使用

所有脚本均可独立运行或以模块方式调用：

```bash
# Hook 1: 注入会话上下文
python3 scripts/session_context.py --hunt-dir ./my-hunt

# Hook 2: 协调器守护检查
python3 scripts/coordinator_guard.py --host example.com --tool ffuf

# Hook 3: 分级审核验证发现
python3 scripts/triage_gate.py --finding finding.json

# Hook 4: 记录工具调用到工作日志
python3 scripts/worklog_recorder.py --type tool_call --tool nmap --hunt-dir ./my-hunt

# Hook 5: 检测代理结论中的过早投降
python3 scripts/retry_detector.py --conclusion "WAF blocked my request" --class xss

# Hook 6: 保存狩猎交接文档
python3 scripts/handoff_saver.py --hunt-dir ./my-hunt --instructions "Continue XSS testing on admin panel"
```

### Kimi 集成

将 `mastermind-bug-bounty/` 放入 Kimi 的 skills 目录即可自动加载：

```
# Kimi 将自动检测并加载 SKILL.md
# 所有 6 个 Hook 成为强制执行的工作流模式
# 参考资料在狩猎过程中按需加载
```

---

## 知识库内容

### `references/hunt_methodology.md` (1,493 行)

完整的自主漏洞赏金方法论，涵盖：
- **侦察** — 子域名枚举、技术指纹识别、JS 分析、API 发现
- **漏洞发现** — 按优先级系统化测试、上下文感知载荷、漏洞链
- **影响验证** — 4 级升级框架、安全数据提取、账户接管 PoC
- **报告与交付** — HackerOne 结构、CVSS 3.1 评分、负责任的披露
- **重试与绕过** — WAF 指纹识别、编码技巧、基于时间的规避

### `references/bug_classes.md` (2,087 行)

10 大类现代漏洞，含检测与利用方法：
- **XSS** — 反射型/存储型/DOM 型/盲打，上下文分析，DOMPurify 绕过，5 轮变异
- **SQL 注入** — 报错/布尔/时间/联合，NoSQL，ORM 模式，二阶注入
- **SSRF** — 基础/盲打，云元数据 (AWS/GCP/Azure)，协议走私，DNS 重绑定
- **CORS** — 三部分可利用性测试，预检绕过，null origin
- **认证** — OAuth/OIDC/PKCE 链路，JWT 攻击 (alg:none, KID)，MFA 绕过
- **授权** — IDOR 模式，路径遍历，批量赋值
- **原型污染** — 跨语言检测，gadget 链，DOMPurify 绕过
- **XML 与文件解析** — XXE 变体，十亿笑声攻击，zip slip
- **基础设施** — 容器逃逸，Kubernetes，S3 桶，无服务器注入
- **业务逻辑** — 竞争条件，价格操纵，工作流绕过

### `references/bypass_techniques.md` (1,443 行)

全面的 WAF/防御绕过百科全书：
- 13 种 WAF 指纹签名（Cloudflare, Akamai, Imperva, AWS WAF, ModSecurity...）
- 编码与变异：URL/HTML/Unicode/大小写变化/空字节
- XSS 专项：20+ HTML5 标签，60+ 事件处理器，协议绕过，模板注入
- SQLi 专项：按数据库类型的注释风格、拼接、空白替代、CASE 注入
- 命令注入：元字符替换、编码技巧、盲注技术
- 速率限制规避：时间抖动、代理轮换、会话管理

### `references/report_templates.md` (1,196 行)

专业报告模板：
- **HackerOne** — 标题格式、CVSS 论证、复现步骤、PoC、影响、修复建议
- **Bugcrowd** — P1-P5 优先级计算、结构化模板、附件要求
- **CVE 申请** — CNA 协调、描述标准、参考格式
- **内部文档** — Obsidian 知识库结构、JSONL 模式、45+ 分类体系

---

## Hook 深度解析

### Hook 1: 上下文注入器

每次会话启动/恢复时，上下文注入器：
1. 读取 `ledger.json` 获取狩猎元数据（目标、范围、状态）
2. 加载 `worklog.jsonl` 最近 30 分钟的条目
3. 从工作日志活动中推导活跃代理状态
4. 如存在，加载上一次会话的 `handoff.md`
5. 将所有信息格式化为注入上下文块

这彻底解决了 "金鱼记忆" 问题 —— AI 精确知道上次停在哪里。

### Hook 2: 协调器守护（软门）

协调器守护执行两项操作规则：
1. **速率限制** — 对同一主机的请求超过 3 次时发出警告（防止枚举喷雾）
2. **委派执行** — 协调器直接运行专家工具而非生成专家代理时发出警告

这是**软门** —— 仅警告和引导，从不拦截。协调器可通过明确确认来覆盖。

### Hook 3: 分级审核门（硬门）

分级审核门是质量支柱。每个发现必须通过：
1. 目标 URL/主机存在
2. 漏洞类型已识别
3. 存在检测证据
4. **影响已证明**（硬门 —— 拒绝仅检测到的影响）
5. 置信度分数 >= 0.70

通过审核的发现触发完整链：**PoC 生成 → 手动证据捕获 → H1 报告草稿 → Caido 录制**

### Hook 4: 工作日志记录器

每次操作产生双输出：
- **JSONL** (`worklog.jsonl`) — 机器可读，结构化，仅追加
- **Obsidian Markdown** (`vault/worklog.md`) — 人类可读，带时间戳和元数据

追踪事件：工具调用、发现、代理生成、代理结论、扫描、技能调用。

### Hook 5: 重试检测器

重试检测器对代理结论进行模式匹配，识别 6 类过早投降：
- **检测到 WAF** → 注入基于编码的绕过策略
- **CDN 拦截** → 尝试替代注入点或基于时间的规避
- **"看起来安全"** → 要求用扩展载荷进行更深入测试
- **403/401** → 尝试授权绕过或替代路径
- **明确投降** → 拒绝并重新部署更严格的要求
- **速率限制** → 应用时间抖动和分布式请求模式

检测器维护重试上限（最多 3 次），防止无限循环。

### Hook 6: 交接保存器

会话结束（或触发 `/compact`）时，交接保存器：
1. 序列化所有活跃目标及其测试状态
2. 捕获进行中及已完成的发现
3. 记录代理状态和任务分配
4. 生成下一步待办清单
5. 保存到 `vault/handoff_TIMESTAMP.md`，包含 YAML 前置元数据

下次会话通过上下文注入器自动加载此交接文档。

---

## 设计哲学

本技能遵循源自 Mastermind 架构的三大核心原则：

**1. 持久性胜于智能**
一个记住每个测试目标、每个发射载荷和每个结论的猎人，每次会话都从零开始的更聪明的猎人表现更优。

**2. 管控胜于过滤**
在分级审核门拦截一个坏发现，比清理一份误报报告便宜 100 倍。在置信度/影响阈值处设置硬门，从根本上保证质量。

**3. 重试胜于投降**
大多数 "WAF 拦截了我" 的结论都为时过早。对失败主义语言进行模式匹配并注入绕过策略，能将 5 分钟的放弃转化为 30 分钟的成功利用。

---

## 贡献指南

欢迎以下方面的贡献：

- **新的绕过技术** —— 添加到 `references/bypass_techniques.md`
- **额外的漏洞类型** —— 扩展 `references/bug_classes.md`
- **脚本改进** —— Python 脚本仅使用标准库，保持零依赖
- **报告模板** —— 添加其他平台的模板（Intigriti, Synack 等）

大型改动前请先开 issue 讨论，确保与架构方向一致。

---

## 许可证

MIT 许可证 —— 详见 LICENSE 文件。

---

## 致谢

- [trace37 labs](https://labs.trace37.com/) —— 原创 Mastermind Hooks Architecture 与研究
- 漏洞赏金社区 —— 方法论源自真实世界的狩猎经验

---

*为那些不满足于仅检测的猎人而构建。*
