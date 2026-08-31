# 控制器 exact-closure 运行时结果（2026-08-31）

## 会话完整性

- 会话：`2f6b7a2b35a7e795760bf1b04fabb301`
- 原始证据：`extracted/analysis/controller-exact-closure-runtime-20260831-p38144-v2/raw-session-2f6b7a2b35a7e795760bf1b04fabb301`
- 事件：164,698
- 停止：`STOPPED_CLEAN`
- 丢失、回压、存储错误：0
- 入口验收：接受；3 个普通点和 2 个聚合调用者均有覆盖，exact-promoted lane 原始 ABI 完整。

## 本轮闭合与否定

- Animator 原生桥 `game + 0x1fc5f030` 在动作窗口内执行 12,206 次；同次调用的子调度边已经观察到。
- 5 个 Behavior 对象候选均观察到后续 Destroy；这只闭合 ObjectCandidate 生命周期，不提升为 Remielle EntityIdentity。
- 7 次 SetTriggerParameter 涉及运行时 task index 215、412、1002；静态祖先链分别机械联接到 `Int_ActiveSkill == 1/2/5` 三条分支，但仍是结构候选。
- 原先预选的 IntComparison 直接调用者 `game + 0xace055` 实际只产生 `ActionMode == 0`、`ActionMode == 1`、`ActionMode != 99`。因此它不是五个 Remielle 静态条件的完整入口，不能据此宣称条件集闭合。

## 下一采集单元

反汇编与本轮 aggregate caller 证据共同锁定两个 `ConditionalEvaluator -> IntComparison` 调用点：

- call `game + 0x1f218996`，返回 `game + 0x1f21899c`
- call `game + 0x1f218a4f`，返回 `game + 0x1f218a55`

两处均满足：evaluator 保存在 RSI、`[RSI+0x60]` 装入条件 task、EDX 清零、经虚表槽 `+0x108` 调用。下一计划只观察现有 IntComparison 物理入口，并仅提升这两个调用者；读取条件 task、evaluator、owner Behavior、task id、SharedInt 名称、常量和操作符。

最终资格化计划：`extracted/analysis/controller-nested-condition-plan-20260831-v4/capture-plan.controller-nested-condition.json`

- 物理入口：1
- exact callers：2
- XMM：关闭
- 自动停止、固定时长、快照上限：均关闭
- 上一会话实测源调用量约 22 次/秒；不再观察造成卡顿的高频父级。
- 原生入口字节、PE `.pdata`、完整解码和 Ghidra CFG 已一致；目标进程资格化仍须在下次进游戏后执行。

本轮没有取得完整控制器。下一轮的明确目标是把两个嵌套调用者产生的运行时条件与五个静态 Remielle 条件做同会话比对，并保留 owner Behavior 对象关系。

## 嵌套条件运行时结果

后续会话 `fa5fde59e655dc32480f2fc80e29ffdb` 已完成该目标：

- 128 个块、2,503 条事件，`STOPPED_CLEAN`，全部校验通过。
- 2,502 条 exact-promoted 样本；两个预选调用者均覆盖。
- 零事件丢失、零读取失败、零截断、零回压。
- 五个静态 Remielle 条件全部在同一会话原始字段中出现：`Int_AIMoveType == 1/2` 与 `Int_ActiveSkill == 1/2/5`。
- 五条目标签名均归于同一个 owner Behavior 对象候选 `0x7010B37EE00`（十进制 `7701064576512`）；evaluator→task 和 task→owner 的现场关系逐事件一致。
- 同一 owner 还产生其他 `Int_ActiveSkill`、`Int_LastActiveSkill` 与 `ActionMode` 条件。它们作为额外原生观察保留，不被冒充为原先静态五节点集合的一部分。
- 当前身份等级仍是 `ObjectCandidate`；本轮没有原生创建代次或 Remielle EntityIdentity 绑定，不能仅凭字段相似把指针提升为实体身份。

分析原件：`extracted/analysis/controller-nested-condition-runtime-20260831-p31252-v2/analysis-v2/controller-nested-condition-runtime-analysis.json`

更新台账：`extracted/analysis/controller-closure-ledger-20260831-v25/controller-closure-state.json`。台账已将本采集单元从“下一次运行时工作”中移除；当前先做 selector 与上游调用边的静态收窄，不要求立即再次运行游戏。
