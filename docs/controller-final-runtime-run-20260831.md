# 控制器最终运行时前沿：单次组合采集协议

## 结论

剩余六类缺口是六项验收结论，不是六次采集。当前可到达的动态缺口已合并为一个 13 点 CapturePlan、一次进程资格化和一次试玩会话。随机 selector、已闭合的 selected-API invoker 边以及完整覆盖窗口内未观察到的旧 job 分支不再重复采集。

普通特殊技是唯一环境相关例外：若试玩继续强制能量全满，本轮只能再次证明该环境中未获得独立覆盖，不能把强化特殊技冒充普通特殊技。以后若出现可自然消耗能量的环境，只需补这一项，不需要重跑其余五项。

## 固定输入

- XXMI 仅加载：`E:\ZZZ\tools\UnifiedCapture\build\UnifiedCapture.dll`
- DLL SHA-256：`95626999822042AEA3F15E439157FCFF09B90E414271A37B7051D040D4768484`
- Source plan：`E:\ZZZ\extracted\analysis\controller-final-runtime-plan-20260831-v2\capture-plan.controller-final-runtime.json`
- Source plan SHA-256：`7F5CD22D204E3788298A76739281E8AA6FDC1199356C8F8017C15617125AD2D4`
- 入口资格请求：`E:\ZZZ\extracted\analysis\controller-final-runtime-qualification-20260831-v1\qualification.json`
- 入口资格请求 SHA-256：`A58F5EF37C90935C1363B8D708B406BCC2093A68902D6778C830F1A51C95E5DC`
- 机械入口清单：`E:\ZZZ\extracted\analysis\controller-final-runtime-p1-20260831-v1\native-exit-manifest.candidate.json`
- 机械入口清单 SHA-256：`80F9C636769738F11B33AF07A34916EBB22BFE393A67099A69E824930AC0C3F4`

`build\bootstrap.json` 保持 `control-only`。不加载旧观察器，不开启 XXMI 不安全模式，不修改保护配置。

## 这一次回答什么

1. `TryLoadBehavior(entityID, Behavior*) -> LoadBehaviorComplete(Behavior*, BehaviorTree*) -> DestroyBehavior(Behavior*)` 是否建立同一原生 Behavior 实例的身份和生命周期边界，并由外部行为名限定到 Remielle。
2. Bool、Integer、Trigger 任务持有的 `UnityEngine.Animator.m_CachedPtr` 是否与 UnityPlayer 参数消费者的原生 `receiver` 相等。
3. 两个已由静态反汇编和既有运行时边验证的 Animator 阶段点，是否能在同一会话中与该 receiver/动作窗口建立关系。
4. 每个标记动作窗口中实际出现了哪些原生参数写入、调用者和阶段事件；未覆盖或有丢失的窗口保持 UNKNOWN。
5. 普通特殊技是否在当前试玩环境中真正出现；强化特殊技不会替代它。

## 激活边界

先通过 XXMI 进入游戏，但停在进入 Remielle 试玩之前。此时运行 `entryctl.py prepare-apply`，让 13 个入口针对本次 PID 和模块加载实例完成资格化。只有结果同时满足以下条件才进入试玩：

- 13/13 sites 完成资格化；
- 返回实际 generation 和 session id；
- 状态为持续采集且无 automatic stop；
- 未出现 patch/restore、admission、storage 或 retention 错误。

## 一次试玩的窗口

每段动作前写入对应 mark；动作不必卡帧，也不要求严格只发生一次：

1. `BASELINE`：进入试玩后静置数秒。
2. `MOVE_SPRINT`：移动与冲刺。
3. `NORMAL_CHAIN`：一套完整普攻。
4. `DODGE_ONLY`：精准闪避后不接普攻。
5. `DODGE_FOLLOWUP`：精准闪避后接普攻。
6. `EX_SPECIAL`：强化特殊技。
7. `SPECIAL_ATTEMPT`：尝试普通特殊技；若环境仍强制强化，照实记录。
8. `SWITCH_ASSISTS`：普通切人；条件允许时包含格挡支援与支援攻击，二者分别记录。
9. `PHASE_FLOW`：转换姿态、切人进入相变时流并让自主行动持续一段时间。
10. `ULTIMATE_CHAIN`：条件允许时执行终结技或连携技；不可达时不伪造覆盖。
11. `LEAVE_COMBAT`：退出接战并退出试玩，在试玩页停留数秒，以取得销毁/退出边界。

## 停止与接受条件

显式执行 `entryctl.py finish`，只接受 `STOPPED_CLEAN`。所有结论还必须检查：进程绑定一致；动作窗口的覆盖和 loss；retention 键级证据；manifest/chunk 完整性；同一地址是否有原生生命周期边界。零记录只能解释为 `NOT_OBSERVED_IN_COVERED_WINDOW` 或 `UNKNOWN`，不能直接解释为行为不存在。
