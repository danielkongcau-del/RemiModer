# Remielle Origin 原生控制器有限完成合同结果

## 结论

`controller-completion-contract.v1` 已将“取得客户端原生控制器定义”限定为 14 个固定核心 Claim。机器计算结果为：

- `core_claims = 14`
- `core_closed = 14`
- `core_open = 0`
- `definition_acquisition_complete = true`
- `runtime_required_now = false`
- `representative_trace_validation_complete = false`
- `independent_reimplementation_complete = false`

这里的完成仅表示：在冻结边界内，Remielle Origin 的权威序列化定义、原生类型/方法/调用点、必要运行时对象关系、动态端点和输出引用已经形成有限且可追溯的取得图。它不表示已经编写可独立运行的替代控制器，也不表示穷举了全部战斗组合。

## 固定完成分母

核心 Claim 为 C01-C14：

1. 模块和范围身份；
2. Remielle Origin 序列化根清单；
3. Animator 状态、transition、selector 拓扑；
4. Behavior Task、变量和条件拓扑；
5. Task/Ability/native 所有权边界；
6. 运行时实例、生命周期和实体身份；
7. Animator receiver 和 stage 绑定；
8. 序列化 action 输出合同；
9. 移动、普攻、闪避、特殊技定义；
10. 切人和支援定义；
11. 相变时流和后台自主行动定义；
12. 终结技和连携定义；
13. 动态原生端点闭合；
14. 证据完整性和有限图闭合。

核心 Claim 只有 `CLOSED` 和 `CLOSED_OPAQUE` 能通过。`ENVIRONMENT_UNAVAILABLE` 和 `OUT_OF_SCOPE` 不能让核心 Claim 自动完成。以后发现新的 engine helper 不会自动扩大该分母；只有证明 C01-C14 中某项不成立，才能产生新的阻塞工作。

`controller_closure_consolidate.py` 保留为历史滚动台账生成器，其旧 `complete_controller=false` 字段不再具有最终验收含义；终态只由本合同计算。

## 分层结果

- 原生定义取得：完成。
- 代表性运行轨迹验证：部分完成，非定义阻塞项。
- 独立可运行重实现：未开始，不属于本合同。
- 188-type/353-callsite 审计：完成，转为 Engine Audit 附录。
- v43 13 个分支输入探针：保留为可选诊断单元，不激活。

普通特殊技的权威结构定义已经由 CurSP 阈值、BranchIndex 写入、状态/结束状态和动画对闭合；试玩环境中的独立执行录像仍为环境相关的可选验证。

## 轨迹一致性

现有 33 个 action window 全部完整且零丢失。为了不把弱身份关系升级为原生因果关系，检查器采用保守规则：

- 1 个窗口具有直接同线程 Remielle Task-to-consumer 见证，记为 `MATCH`；
- 3 个准备/收尾窗口记为 `NOT_APPLICABLE`；
- 29 个窗口只具有同地址活动或没有充分见证，记为 `UNKNOWN`；
- 0 个 `MISMATCH`；
- 不因此产生核心阻塞项，也不要求立即运行游戏。

`UNKNOWN` 表示当前窗口不足以证明完整因果链，不表示动作未执行或控制器定义缺失。

## 权威产物

- `extracted/analysis/controller-native-evidence-graph-20260831-v6/controller-native-evidence-graph.json`
- `extracted/analysis/controller-completion-contract-20260831-v2/controller-completion-contract.v1.json`
- `extracted/analysis/controller-completion-contract-20260831-v2/controller-completion-state.json`
- `extracted/analysis/controller-completion-contract-20260831-v2/controller-engine-audit-appendix.json`
- `extracted/analysis/controller-evidence-model-20260831-v2/remielle-controller-evidence-model.json`
- `extracted/analysis/controller-trace-conformance-20260831-v2/controller-trace-conformance.json`

证据模型是只读索引：未知关系返回 `UNKNOWN`，opaque leaf 返回原生 RVA/body/ABI 或字段合同，不合成 transition、不添加预测默认值、不发明原始名称，也不能直接驱动角色。

## 重现命令

```powershell
python E:\ZZZ\tools\UnifiedCapture\controller_completion_contract.py `
  --graph E:\ZZZ\extracted\analysis\controller-native-evidence-graph-20260831-v6\controller-native-evidence-graph.json `
  --out E:\ZZZ\extracted\analysis\controller-completion-contract-20260831-v2

python E:\ZZZ\tools\UnifiedCapture\controller_evidence_model.py `
  --graph E:\ZZZ\extracted\analysis\controller-native-evidence-graph-20260831-v6\controller-native-evidence-graph.json `
  --completion E:\ZZZ\extracted\analysis\controller-completion-contract-20260831-v2\controller-completion-state.json `
  --out E:\ZZZ\extracted\analysis\controller-evidence-model-20260831-v2

python E:\ZZZ\tools\UnifiedCapture\controller_trace_conformance.py `
  --model E:\ZZZ\extracted\analysis\controller-evidence-model-20260831-v2\remielle-controller-evidence-model.json `
  --windows E:\ZZZ\extracted\analysis\action-window-receiver-attribution-20260831-v1\action-window-receiver-attribution.json `
  --out E:\ZZZ\extracted\analysis\controller-trace-conformance-20260831-v2
```

输出目录是不可变的；复跑必须使用新的版本目录。
