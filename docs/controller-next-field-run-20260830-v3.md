# 控制器字段与因果前沿：下一轮单会话协议 v3

本文是本地操作协议，不是游戏行为已经发生的证据。它替代 v2 的纯 caller-retained 计划；历史协议和历史采集原件保持不变。

## 固定输入

- XXMI 只加载：`E:\ZZZ\tools\UnifiedCapture\build\UnifiedCapture.dll`
  - SHA-256：`588CBB1CA039AA5F58CAE3C34D5409E7DE3C374D5048881C261BF90F8A4D7E6A`
- 41 点字段增强保留式计划：
  `E:\ZZZ\extracted\analysis\controller-field-read-plan-20260830-v1\capture-plan.field-enriched.json`
  - SHA-256：`8AC46886E5A901B64895883438C748640EF40D300BB023F3CBDFFEEFE9058524`
- 41 点资格请求：
  `E:\ZZZ\extracted\analysis\controller-causal-frontier-qualification-20260830-v2\qualification.json`
  - SHA-256：`E5CA3F81D2BE27B7972BD63FC0B9FDEABDD4E4F4FB1B235B6FBEEBC229D2D7BF`
- 原生入口清单：
  `E:\ZZZ\extracted\analysis\controller-causal-frontier-p1-source-bound-20260830-v2\native-exit-manifest.source-bound.json`
  - SHA-256：`E78478AD8AE0CA0AA2FE32D9573C639E6909DBE233DB0CE710CFB58D355B63D6`

`build\bootstrap.json` 保持 `control-only`。不启用 XXMI 不安全模式，不改变保护设置，不加载旧观察器 DLL。

## 本轮新增证据

- 10 个 Behavior task 点：记录任务对象自身已收割字段，包括参数对象、Animator/Entity 候选、参数 hash 和 `setOnce`。
- 5 个 ODKPBBAJAEG 生命周期点：记录 EcsSystem/Filter/JobHandle 原始字段；只在 `Update` 追读 EcsFilter，避免构造期的预期空指针。
- 1 个 `ParallelForJobStruct<IKNHGFBHLLK>.Execute`：记录 RCX/RDX/R8/R9、第五栈参数及原始 JobRanges 窗口。
- 5 个历史高频点继续按 entry return address 精确计数，每 caller 只保留一份完整样本。现有丢失样本显示部分点的 RCX 基数可达数千至 23173，因此本轮不擅自把全部点改成 RCX 复合键。

字段标签均绑定 `dump-x-xa.cs`、运行时方法反射和原生指令证据；它们不会自动升级成 ObjectInstance、EntityIdentity 或控制器语义。

## 激活

用户通过 XXMI 启动游戏并停在进入试玩之前。随后用实际 PID 和一个尚不存在的运行目录执行：

```powershell
python E:\ZZZ\tools\UnifiedCapture\entryctl.py prepare-apply `
  --pid <PID> `
  --qualification E:\ZZZ\extracted\analysis\controller-causal-frontier-qualification-20260830-v2\qualification.json `
  --manifest E:\ZZZ\extracted\analysis\controller-causal-frontier-p1-source-bound-20260830-v2\native-exit-manifest.source-bound.json `
  --plan E:\ZZZ\extracted\analysis\controller-field-read-plan-20260830-v1\capture-plan.field-enriched.json `
  --out <RUN_DIR>
```

只有命令返回 41 个资格点、实际 generation、session id 和 `ENTRY_UNIT_RUNNING_NO_AUTOMATIC_STOP` 后才进入试玩。

## 单会话动作

本轮不要求完美卡帧。用标记分隔以下可用动作：

1. `BASELINE_AND_ENGAGE`：进入试玩、静置、移动/冲刺、接战。
2. `TASK_AND_PARAMETER`：普攻链、强化特殊技、精准闪避（无衔接及衔接）、普通切人。
3. `SUPPORT_AND_MECHANIC`：格挡支援、支援攻击、转换姿态、相变时流、长按虚曜招式。
4. `ULTIMATE_AND_RESET`：终结技、后摇、切人或行为中断，尽量触发 task reset。
5. `DISENGAGE_AND_EXIT`：脱战尝试、退出战斗并在试玩页停留片刻。

试玩能量固定导致普通特殊技不可独立触发时，明确记为 `UNAVAILABLE_IN_TRIAL`，不把强化特殊技冒充普通特殊技，也不为此反复重做。

标记命令：

```powershell
python E:\ZZZ\tools\UnifiedCapture\capturectl.py mark --pid <PID> <LABEL>
```

## 正常停止与验收

退出战斗后执行：

```powershell
python E:\ZZZ\tools\UnifiedCapture\entryctl.py finish --pid <PID> --run <RUN_DIR> --wait-seconds 30
```

只接受 `STOPPED_CLEAN`。验收同时检查：

- 5 个保留点的 caller count 完整，且无 retention capacity/key/busy 损失；
- Exact 流没有 pool、store、pair、read、truncation 或 frame-termination 缺口；
- 新字段读取成功率及失败 QPC 范围；
- Task/Ability、Animator consumer、ECS/Job 是否在同一标记窗口形成对象候选和调度关系；
- manifest 链、chunk CRC32C/SHA-256 和可重建索引完整。

本轮结束后才依据真实键基数选择局部复合键或 exact promotion；不会把一次字段采集宣称为完整控制器。
