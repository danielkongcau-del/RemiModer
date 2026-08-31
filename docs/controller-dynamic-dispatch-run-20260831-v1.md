# Ability 动态调度身份：单次运行协议 v1

## 目标与边界

本轮不是重录已经闭合的动画链，也不要求用户按固定帧执行动作。它只补静态证据无法给出的两类进程内真值：

1. 在 `BehaviorManager.LoadBehaviorComplete` 的低频边界读取 21 个已确认初始化、但磁盘镜像中没有最终值的调度槽。
2. 在 36 个动态调用点中，仅对本次实际执行的点记录原始 receiver、`Il2CppClass*`、类名指针/字符串和最终调用目标。一个相邻 Bullet 调用点共享同一物理探针，因此动态调用点 36 个、物理动态探针 35 个。

未执行的调用点保持 `NOT_OBSERVED_IN_COVERED_WINDOW` 或 `UNKNOWN`；类名、地址连续性和时间接近均不会自行升级为方法语义、ObjectInstance 或 EntityIdentity。

## 固定输入

- XXMI 只加载：`E:\ZZZ\tools\UnifiedCapture\build\UnifiedCapture.dll`
- DLL SHA-256：`1BF254C21F2BEEDD319179CA61149B3F529A94F27FE3F358EFB60B9E63D4BD4C`
- Source plan：`E:\ZZZ\extracted\analysis\ability-dynamic-dispatch-plan-20260831-v17\capture-plan.ability-dynamic-dispatch.json`
- Source plan SHA-256：`D1B49323EB1F38A15D1C6D4FE0E9F28A186C82793F10F6340AFC9943678246A8`
- 资格请求：`E:\ZZZ\extracted\analysis\ability-dynamic-dispatch-plan-20260831-v17\qualification.json`
- 资格请求 SHA-256：`C38E61943AFC6579564766009FF7030C6E61076BD7D85FACB4EB607484D6E502`
- 闭合总账：`E:\ZZZ\extracted\analysis\controller-closure-ledger-20260831-v38\controller-closure-state.json`
- 总账 SHA-256：`27B8148FA258DA46BE8E6D384DD45C7C2A9C1E8F2C91AA609A12DD3737AA7D55`

`build\bootstrap.json` 保持 `control-only`。不加载旧观察器，不启用 XXMI 不安全模式，不修改保护配置。

## 启动与资格化

用户通过 XXMI 进入游戏，但先停在进入 Remielle 试玩之前。取得 PID 后，创建一个全新的运行目录并执行：

```powershell
$Run = 'E:\ZZZ\extracted\analysis\ability-dynamic-dispatch-runtime-<date>-p<PID>-v1'
New-Item -ItemType Directory -Path $Run

python E:\ZZZ\tools\UnifiedCapture\capturectl.py qualify-sites `
  --pid <PID> `
  --out "$Run\qualification-evidence.json" `
  E:\ZZZ\extracted\analysis\ability-dynamic-dispatch-plan-20260831-v17\qualification.json

python E:\ZZZ\tools\UnifiedCapture\p1_apply_instruction_qualification.py `
  --plan E:\ZZZ\extracted\analysis\ability-dynamic-dispatch-plan-20260831-v17\capture-plan.ability-dynamic-dispatch.json `
  --evidence "$Run\qualification-evidence.json" `
  --out "$Run\qualified-plan"

python E:\ZZZ\tools\UnifiedCapture\capturectl.py apply `
  --pid <PID> `
  "$Run\qualified-plan\instruction-plan.target-qualified.json"

python E:\ZZZ\tools\UnifiedCapture\capturectl.py start --pid <PID>
```

只有 36/36 点资格化、三处 near-only 点实际选择 5 字节重定向、计划成功给出本次 generation/session，且 `status` 无 loss/storage/hook 错误时，才通知用户进入试玩。若任一 near-only 点需要 16 字节远跳，运行时必须恢复并拒绝激活，不能放宽合同。

## 一次试玩覆盖

本轮使用宽动作覆盖，不要求严格顺序或纯净窗口。建议按下列标签分段；自然发生的额外动作保留：

1. `BASELINE`：进入试玩后短暂静置。
2. `MOVE_DODGE_ATTACK`：移动、冲刺、闪避、普攻链。
3. `SKILL_ULT`：强化特殊技和可用的终结技。
4. `SWITCH_ASSIST_CHAIN`：普通切人、格挡支援、派生攻击、可达的双向连携技。
5. `PHASE_FLOW`：长按特殊技进入转换姿态；一次不切人落地，一次切人进入相变时流并让 Remielle 自主行动；可达时普通换入与长按普攻。
6. `LEAVE_TRIAL`：退出接战并离开试玩，在试玩前页面停留片刻。

每段开始前由本地控制端执行：

```powershell
python E:\ZZZ\tools\UnifiedCapture\capturectl.py mark --pid <PID> <LABEL>
```

这不是“六次采集”，而是同一 generation、同一证据会话中的六个分析边界。试玩不能触发的 mixin/调用点不要求用户反复盲试。

## 停止与接受

```powershell
python E:\ZZZ\tools\UnifiedCapture\capturectl.py stop --pid <PID> --drain
```

只接受 `STOPPED_CLEAN`，并核对：

- 资格证据、v2 计划和证据 session 的进程身份一致；
- 36 个资格点均完成资格化时的恢复；正式停止后逐项核对本轮实际 HookOwnership 安装与撤销结果，不预设一个与实际共享关系无关的固定 hook 数；
- loss、read failure、backpressure、storage failure 和未知尾部均单独核算；
- 21 个槽值按模块范围和已知代码头机械分类；
- 动态点仅报告实际读取到的对象、类和目标，不凭类名猜方法名；
- 同一地址只有在原生生命周期证据支持时才建立 ObjectInstance；否则停留在 ObservedAddress/ObjectCandidate。
