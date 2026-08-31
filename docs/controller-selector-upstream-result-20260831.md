# Selector 与上游调用边处理结果（2026-08-31）

## 结论

剩余缺口是六项独立验收声明，不等于六个采集单元。当前处理已离线消除其中一项完整缺口，并从 Task/Ability 调度缺口中消除了 selector 子问题：

- `selected Unity API target → Animator invoker → selected bridge` 已闭合为同一次调用链，不需要重新进游戏。
- Remielle Origin `Confrontation` 中两个 `RandomExcuteWithSharedWeight` 节点的两个子分支均已有原生运行时执行边，共四条；selector 选择不需要重新采集。
- 控制器台账由 6 个运行时缺口降为 5 个，且当前仍应先做静态收窄，`runtime_required_now=false`。

## 上游调用边证据

静态完整反汇编证明：

- Unity API 目标函数：`GameAssembly + 0xACDFE0`。
- 唯一 invoker 字段调用：`GameAssembly + 0xACE052`，指令 `ff5710 / call qword ptr [rdi+0x10]`。
- 调用后续地址：`GameAssembly + 0xACE055`。
- 被计划直接观察的 invoker：`GameAssembly + 0x4E30`。

既有精确运行时证据在 `0x4E30` 入口记录到的 exact caller return RVA 正是 `0xACE055`，并已在同一次 invoker 调用内观察到选定 bridge `GameAssembly + 0x1FC5F030`。因此链路不是靠时间邻近推断，而是由静态 callsite、精确返回地址和同调用 bridge 记录共同联接。

权威工件：

- `extracted/analysis/controller-upstream-invoker-join-20260831-v1/controller-upstream-invoker-join.json`

## Selector 证据

AB 原生树中 scoped 节点为：

- `Behavior_Avatar_RemielleOrigin_Confrontation` task 3，子节点 4、21。
- 同一树 task 45，子节点 46、63。

两组序列化 SharedFloat 权重均为原始值 `1.0 / 1.0`。保存的运行时结构联接将它们分别映射到 runtime task 54 和 96，并观察到：

- runtime 54 → 55：21 次；54 → 72：17 次。
- runtime 96 → 97：9 次；96 → 114：4 次。

这证明两个 selector 的两个原生子分支都实际被选择过。边界仍保留：这是完整 loader graph 与任务结构的机械联接，不宣称运行时直接读到了 CAB/PathID；旧日志中的 `entityID` 字段也没有被提升为新版证据模型中的 `EntityIdentity`。

权威工件：

- `extracted/analysis/controller-selector-static-runtime-join-20260831-v1/controller-selector-static-runtime-join.json`

## 剩余五项运行时缺口及采集组合

1. 同一实例 Animator stage → 参数 consumer 因果关系。
2. Task/Ability → Animator 的其他跨线程/异步调度边；五个条件和两个 selector 已不再属于该缺口。
3. 原生对象生命周期 → Remielle `EntityIdentity`。
4. 普通特殊技的独立运行覆盖。
5. 每招式归属及完整 entry/leave 配对。

设计上不应做五次独立试玩。前三项和第 5 项可由一份组合 `CapturePlan`、一次进程激活、一个带多个 mark 的主会话完成；生命周期点必须在进入试玩前安装。普通特殊技在当前试玩“能量始终满”的约束下可能不可自然触发，因此不能承诺与主会话一次做全。合理预期是“一次主采集 + 仅在获得普通特殊技可达条件时的一次补充”，而不是按缺口逐项重复采集。

在生成该组合计划前，仍需静态定位其他异步调度 callsite 与对象创建点，以免再次放入高频宽观察点。

## 验证

- 新增两个独立分析器及测试。
- UnifiedCapture 全套测试：`133 passed`。
- 最新台账：`extracted/analysis/controller-closure-ledger-20260831-v28/controller-closure-state.json`。
- 台账 SHA-256：`caee34ab7c8072ca20b435665b4abf4a721c2c90e1d23292a2954309261285d1`。
- 统计：31 个 bounded closed、1 个 offline open、5 个 runtime open、控制器尚未完整获取。
