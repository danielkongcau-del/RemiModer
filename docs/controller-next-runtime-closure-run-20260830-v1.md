# 控制器剩余因果链：窄化运行时采集协议 v1

本文是下一次本地采集的可重复操作协议，不是行为已经发生的证据。历史会话和逆向原件保持不变。

## 固定输入

- XXMI 只加载：`E:\ZZZ\tools\UnifiedCapture\build\UnifiedCapture.dll`
  - SHA-256：`43765B20EF5E6FF68E0B349D73E5EF471661463F69C37B05261EF3F22C1F8AD6`
- 27 点窄化计划：
  `E:\ZZZ\extracted\analysis\controller-runtime-closure-plan-20260830-v1\capture-plan.runtime-closure.json`
  - SHA-256：`DD015EE6962AA92054E0E655C53E0CD971DBD70F78BC5988EAC7AF118DBE4DAE`
- 27 点资格请求：
  `E:\ZZZ\extracted\analysis\controller-runtime-closure-qualification-20260830-v1\qualification.json`
  - SHA-256：`7DA16730C78063DE6F3B2D0F6110668B3A64F0B8DCDA15B79FAF842AF04A0792`
- 机械原生入口清单：
  `E:\ZZZ\extracted\analysis\controller-runtime-closure-p1-20260830-v1\native-exit-manifest.candidate.json`
  - SHA-256：`4A691854BBE53B37F9961C59E92DE5740784150CADBC349498DB4FABE6652A61`

`build\bootstrap.json` 保持 `control-only`。不启用 XXMI 不安全模式，不修改保护设置，不加载旧观察器 DLL。

## 本轮只回答四个问题

1. 原生 invoker `0x4e30` 是否在本次进程中以 `RCX = GameAssembly + 0x1fc5f030` 调用 Animator fixed-update bridge。
2. `ODKPBBAJAEG.KBPGJAPPBLI` 是否进入 `BehaviorManager.Tick -> RunTask -> 已选 task callback` 同步链。
3. 已选 task 对象地址是否能跨 OnStart/OnUpdate/OnReset 形成候选连续性；这仍不自动升级为 ObjectInstance。
4. Remielle 的相变时流相关操作是否选择 `IKNHGFBHLLK -> shared body -> ODK consumer` 分支；无命中时只在完整覆盖窗口内报告未观察。

本轮不重新监听约五千万调用量的 `GameAssembly.selected-api-target@0xacdfe0` 或高频 Animator 总阶段。Invoker 的代码目标比较值不是固定绝对地址：入口资格化取得本次 `module_base` 后，`p1_apply_entry_qualification.py` 才把 `game + 0x1fc5f030` 绑定为普通入口谓词，并写出独立绑定原件。

## 激活

通过 XXMI 启动游戏，停在进入试玩之前。随后运行：

```powershell
python E:\ZZZ\tools\UnifiedCapture\entryctl.py prepare-apply `
  --pid <PID> `
  --qualification E:\ZZZ\extracted\analysis\controller-runtime-closure-qualification-20260830-v1\qualification.json `
  --manifest E:\ZZZ\extracted\analysis\controller-runtime-closure-p1-20260830-v1\native-exit-manifest.candidate.json `
  --plan E:\ZZZ\extracted\analysis\controller-runtime-closure-plan-20260830-v1\capture-plan.runtime-closure.json `
  --out <NEW_RUN_DIR>
```

只在结果同时给出 27 个资格点、实际 generation、session id、`ENTRY_UNIT_RUNNING_NO_AUTOMATIC_STOP`，并且派生报告显示 `runtime_predicate_bindings=1` 后进入试玩。

## 一次试玩内的动作

动作不需要卡帧，也不要求重做所有招式：

1. `BASELINE`：进入试玩后静置数秒。
2. `TASK_CHAIN`：移动、普攻、一次强化特殊技、一次精准闪避、一次普通切人。
3. `PHASE_FLOW_JOB`：按角色原生机制进入转换姿态，切人使 Remielle 进入相变时流，让自主行动持续约十秒。
4. `RESET_AND_EXIT`：中断一次可中断行为，退出接战/退出试玩，在试玩页停留数秒。

每段前执行：

```powershell
python E:\ZZZ\tools\UnifiedCapture\capturectl.py mark --pid <PID> <LABEL>
```

格挡支援、支援攻击和终结技不是本轮四条因果问题的必要动作；若自然发生可以保留，但不要求重复。

## 停止与验收

```powershell
python E:\ZZZ\tools\UnifiedCapture\entryctl.py finish `
  --pid <PID> --run <NEW_RUN_DIR> --wait-seconds 30
```

只接受 `STOPPED_CLEAN`。还必须检查：资格化进程身份和 predicate binding 一致；所有正式动作窗口 admission/loss 为零；retention 无 capacity/key/busy 缺口且每键代表样本已落盘；manifest/chunk 完整；四个问题分别给出 OBSERVED、NOT_OBSERVED_IN_COVERED_WINDOW 或 UNKNOWN，禁止把零记录直接写成行为不存在。
