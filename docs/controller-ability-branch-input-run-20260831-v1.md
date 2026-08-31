# Ability 未命中分支输入：单次合并运行协议 v1

## 目标与边界

本轮只读取 14 个未命中原生调用路径各自选定门条件的机器输入。两个 Summon 逻辑点共享同一条路径守卫，因此实际为 13 个物理指令探针。

- 10 个点是完整机械 CFG 中的强支配单结果门。
- 4 个点只是最邻近的非支配路径守卫，不能据此宣称它们是玩法条件。
- 两个已经静态闭合字段来源的点同时读取寄存器值和原生字段链，作为一致性对照。
- 记录只解释为零值/非零值与原生分支方向；不命名玩法谓词，不猜动作与点位对应关系。

## 固定输入

- XXMI 只加载：`E:\ZZZ\tools\UnifiedCapture\build\UnifiedCapture.dll`
- DLL SHA-256：`1BF254C21F2BEEDD319179CA61149B3F529A94F27FE3F358EFB60B9E63D4BD4C`
- Source plan：`E:\ZZZ\extracted\analysis\ability-unobserved-branch-runtime-plan-20260831-v3\capture-plan.ability-unobserved-branch-input.json`
- Source plan SHA-256：`4BED9CA80579241679F764F40FECBC1B837BD2AE0A37EAFDBA67FD9EB280B052`
- 资格请求：`E:\ZZZ\extracted\analysis\ability-unobserved-branch-runtime-plan-20260831-v3\qualification.json`
- 资格请求 SHA-256：`CA26A44917AC9F812B11695D2DA48F14577BF7C82EF57FB4354F9FC710B9EC34`
- 静态合同：`E:\ZZZ\extracted\analysis\ability-unobserved-branch-runtime-plan-20260831-v3\ability-unobserved-branch-runtime-contract.json`
- 静态合同 SHA-256：`4F862BC0ABB9DD27A0AF6D170DE3F239AA980479960469CDD6F6907F29194168`
- 闭合总账：`E:\ZZZ\extracted\analysis\controller-closure-ledger-20260831-v43\controller-closure-state.json`
- 总账 SHA-256：`FBB6E05DAC5914FFF13DFEB3E4DC1AEE1C9827AD36B5F29C65031076C25E31D9`

`build\bootstrap.json` 继续保持 `control-only`。不加载旧观察器，不启用 XXMI 不安全模式，不修改保护配置。

## 启动、资格化与激活

用户通过 XXMI 进入游戏，先停在进入 Remielle 试玩之前。取得 PID 后，在同一进程内执行：

```powershell
$Run = 'E:\ZZZ\extracted\analysis\ability-branch-input-runtime-20260831-p<PID>-v1'
New-Item -ItemType Directory -Path $Run

python E:\ZZZ\tools\UnifiedCapture\capturectl.py qualify-sites `
  --pid <PID> `
  --out "$Run\qualification-evidence.json" `
  E:\ZZZ\extracted\analysis\ability-unobserved-branch-runtime-plan-20260831-v3\qualification.json

python E:\ZZZ\tools\UnifiedCapture\p1_apply_instruction_qualification.py `
  --plan E:\ZZZ\extracted\analysis\ability-unobserved-branch-runtime-plan-20260831-v3\capture-plan.ability-unobserved-branch-input.json `
  --evidence "$Run\qualification-evidence.json" `
  --out "$Run\qualified-plan"

python E:\ZZZ\tools\UnifiedCapture\capturectl.py apply `
  --pid <PID> `
  "$Run\qualified-plan\instruction-plan.target-qualified.json"

python E:\ZZZ\tools\UnifiedCapture\capturectl.py start --pid <PID>
python E:\ZZZ\tools\UnifiedCapture\capturectl.py mark --pid <PID> BRANCH_INPUT_BEGIN
```

只有 13/13 资格点均成功选择合同允许的 5 字节近跳、资格化阶段全部恢复、计划绑定同一进程并成功开始，才通知用户进入试玩。

## 一次试玩

用户在同一试玩内自然覆盖移动、闪避、普攻、强化特殊技、切人/支援、可达的终结技/连携技和相变时流，然后退出试玩。无需严格顺序，无需逐动作停下来通知，也不要求完美复现全部机制。

退出试玩后执行：

```powershell
python E:\ZZZ\tools\UnifiedCapture\capturectl.py mark --pid <PID> BRANCH_INPUT_END
python E:\ZZZ\tools\UnifiedCapture\capturectl.py stop --pid <PID> --drain
```

只接受 `STOPPED_CLEAN`、完整覆盖、零事件丢失、零读取失败、零截断和完整存储。随后使用预先完成的 `ability_unobserved_branch_runtime_analyze.py` 联接 13 个物理谓词输入与 14 条原生源路径。未观察点仍保持 `NOT_OBSERVED_IN_COMPLETE_COVERED_SESSION`，不能升级成“行为没有执行”。
