# 控制器因果前沿：下一轮保留式采集协议 v2

本文是本地操作协议，不是游戏行为已经发生的证据。它替代旧协议中已过期的观察器哈希，但不修改旧协议或任何历史采集原件。

## 固定输入

- 观察器：`E:\ZZZ\tools\UnifiedCapture\build\UnifiedCapture.dll`
  - SHA-256：`8D2C411DE1ECA2DB2CD2E208B980181A6F345032C02E2A9B34039D1488486762`
- 41 点保留式计划：
  `E:\ZZZ\extracted\analysis\controller-causal-frontier-retained-20260830-v1\capture-plan.caller-retained.json`
  - SHA-256：`5D6EDF39334181DB815C410DBF42E201A2B530BCE4A03BF69B87CA416B614F15`
- 41 点资格请求：
  `E:\ZZZ\extracted\analysis\controller-causal-frontier-qualification-20260830-v2\qualification.json`
  - SHA-256：`E5CA3F81D2BE27B7972BD63FC0B9FDEABDD4E4F4FB1B235B6FBEEBC229D2D7BF`
- 原生入口清单：
  `E:\ZZZ\extracted\analysis\controller-causal-frontier-p1-source-bound-20260830-v2\native-exit-manifest.source-bound.json`
  - SHA-256：`E78478AD8AE0CA0AA2FE32D9573C639E6909DBE233DB0CE710CFB58D355B63D6`

观察器兼容计划现有的 `first_per_entry_return_address`。新复合键能力不会在没有证据表明“同一 caller 多路复用不同原始对象”前擅自改变本轮计划。

## 激活

XXMI 只加载上述 DLL；不启用不安全模式，不改变保护设置。游戏停在进入试玩前时，用实际 PID 替换 `<PID>`，选择一个尚不存在的 `<RUN_DIR>`：

```powershell
python E:\ZZZ\tools\UnifiedCapture\entryctl.py prepare-apply `
  --pid <PID> `
  --qualification E:\ZZZ\extracted\analysis\controller-causal-frontier-qualification-20260830-v2\qualification.json `
  --manifest E:\ZZZ\extracted\analysis\controller-causal-frontier-p1-source-bound-20260830-v2\native-exit-manifest.source-bound.json `
  --plan E:\ZZZ\extracted\analysis\controller-causal-frontier-retained-20260830-v1\capture-plan.caller-retained.json `
  --out <RUN_DIR>
```

只有命令报告 41 个资格点、真实 generation 和已武装状态后才进入试玩。

## 单会话动作与标记

在同一试玩会话中按可用性完成：基础移动/冲刺/闪避、普攻链、强化特殊技、精准闪避两种衔接、格挡支援、支援攻击、双向普通切人、转换姿态与相变时流、长按消耗虚曜、终结技、后摇及脱战尝试。不可用动作明确记为不可用，不以猜测补齐。

每组动作前执行：

```powershell
python E:\ZZZ\tools\UnifiedCapture\capturectl.py mark --pid <PID> <LABEL>
```

建议标签依次为 `BASELINE`、`CORE_ATTACKS`、`DEFENCE_SUPPORT`、`CHARACTER_MECHANIC`、`ULTIMATE_AND_EXIT`。

## 正常停止

退出战斗后执行：

```powershell
python E:\ZZZ\tools\UnifiedCapture\entryctl.py finish --pid <PID> --run <RUN_DIR> --wait-seconds 30
```

只接受 `STOPPED_CLEAN`。本轮 caller 发现还要求所有保留点均为 `complete_for_caller_counts=true`、无 retention key/capacity/busy 损失、每个键有已持久化代表样本、manifest 链完整。Exact 流若出现 `exact_coverage_end_qpc`，该代次在该 QPC 后永久视为有缺口，后续记录不会把它重新标成完整。

停止后的同一进程可继续完成 caller 选择、当前进程入口资格、caller continuation 资格及精确计划激活；无需重编译 DLL。只有原始证据证明同一 caller 下存在多路原始接收者时，才派生 `first_per_composite_key` 后续计划。
