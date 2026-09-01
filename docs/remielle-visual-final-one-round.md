# Remielle Origin 视觉链最终单轮采集

## 目的

本轮只补静态文件无法证明的四类事实：

1. Origin 主页面 `WeatherConfig` 的反序列化后对象字节与 Unity 原生身份。
2. 实际动作期间创建的 `MonoEffect`、其渲染器／材质／灯光／粒子／Behaviour 数组，以及观察到的销毁边界。
3. 参与运行的旧布局 Behaviour 的真实 `Il2CppClass` 名称和当前对象字节。
4. 当前 Nap 相机从 `+0x240` 模块表取出的启用模块、`Nap+0x258` EJK 字段、EJK 输出状态和 Unity 提交链之间的现场关系。

模型几何、材质、贴图、DXBC、12 组 Post/Skin 槽、描边／阴影公式、 authored camera、共享 flare、AssetPath 哈希联接和 GroundLighting 的有限静态缺席均已离线闭合，不在本轮重复采集。

## 启动边界

- XXMI 的 `Inject Libraries` 只保留：
  `E:\ZZZ\tools\UnifiedCapture\build\UnifiedCapture.dll`
- 不加载旧 Animator、Wwise、Behavior 或其他观察器。
- XXMI“不安全模式”保持关闭。
- 游戏进入普通主界面后停下；在统一计划激活前，不要打开 Remielle 页面，也不要进入试玩。
- 没有固定采集时长、15 秒窗口或 200 快照上限。

## 采集端命令

下列命令由 Codex 在用户报告“已进入游戏、尚未打开 Remielle 页面”后执行。`<PID>` 与输出目录在当次进程确定，不能跨进程复用。

```powershell
python E:\ZZZ\local-only\visual-acquisition\visual_final_ctl.py prepare-apply `
  --pid <PID> `
  --out E:\ZZZ\extracted\analysis\remielle-visual-final-live-<PID>-v1
```

只有返回 `ARMED_NO_AUTOMATIC_STOP`、8/8 站点资格化、实际 generation 和 session directory 后，才开始下面的游戏操作。

## 唯一一次试玩路线

顺序不要求卡帧；不要为某一击重来。尽量在同一次试玩中完成：

1. 打开 Remielle 的 **Origin** 主页面／角色展示页，停留数秒，让主页面 Timeline 和 Weather 配置完成一次装载。
2. 进入试玩一次，先短暂停留待机并转动一次展示视角。
3. 移动、冲刺、普通闪避、精准闪避；精准闪避后分别做一次“不接攻击”和“接普攻”。
4. 完成一套普攻链。
5. 完成强化特殊技；随后完成一次“进入转换姿态但不切人、自由落地”。
6. 再次进入转换姿态并切人，触发相变时流；让 Remielle 自主行动数秒。
7. 若本次自然满足条件，换回 Remielle 触发花羽轮舞，再长按普攻发动垂虹／惊鸿。
8. 完成格挡支援及派生攻击、支援攻击。
9. 释放终结技。
10. 若失衡条件允许，分别完成一次“其他角色连携切入 Remielle”和“Remielle 连携切出”；若本轮客观未触发，不重开试玩，报告为覆盖窗口内未观察。
11. 退出试玩回到页面并等待数秒，使本轮可销毁的效果有机会经过真实 `MonoEffect.OnDestroy`。

试玩强制满能量造成普通特殊技无法自然触发，不要求为此另开第二轮。普通特殊技的 authored 控制器／资产关系保留静态权威证据；本轮不会把“未现场执行”写成“该机制不存在”。

## 停止与分析

用户完成上述路线并已经退出试玩后执行：

```powershell
python E:\ZZZ\local-only\visual-acquisition\visual_final_ctl.py finish `
  --pid <PID> `
  --run E:\ZZZ\extracted\analysis\remielle-visual-final-live-<PID>-v1
```

只有 `STOPPED_CLEAN` 才进入分析：

```powershell
python E:\ZZZ\local-only\visual-acquisition\analyze_visual_final_round.py `
  --session-dir <final-status.directory> `
  --final-status E:\ZZZ\extracted\analysis\remielle-visual-final-live-<PID>-v1\final-status.json `
  --out E:\ZZZ\extracted\analysis\remielle-visual-final-analysis-<PID>-v1
```

## 验收

- 会话、块和 manifest 干净封存，8 个必需点的独立丢失账本为零。
- 至少一条完整 Origin Weather 记录。
- 至少一条 V01 效果装配与 V02 已提交 AssetPath 身份的同线程、同 HDF、同 MonoEffect 最近前驱联接，且五类指针数组完整。
- V05 的 EJK/IGO `CameraState` 拷贝零差异。
- V06 在原生 `Nap+0x240` 遍历调用点观察到当前模块等于 `Nap+0x258`，该模块 `+0x68` 回指同一 Nap，并与 V05 的 EJK 地址联接。
- 只对实际观察到的销毁建立生命周期结束；窗口结束仍存活的对象保留“结束边界未知”，不伪造销毁。
- 零事件只写 `NOT_OBSERVED_IN_COVERED_WINDOW` 或 `UNKNOWN_COVERAGE_GAP`，绝不提升为“行为没有发生／组件不存在”。

若必需点有截断、存储回压、资格化失败或无法机械归因的读失败，本轮不被宣布闭合。若一个依赖读取失败，但同一回调已经成功捕获其上游指针为 null，则原始失败仍保留，语义层可将该依赖对象解释为结构性缺席；不得把这类归因反写为“原始零丢失”。

## 实际结果

本轮已经封存并完成机械重放。核心视觉运行时证据闭合，但原四项合约仍有两个字节级缺口：Origin Weather 精确消费者零命中，以及一个实际参与的 `MonoEffectPluginAudio` 只取得指针／cached-list 成员关系、未取得对象字节。详见 `docs/remielle-visual-byte-closure-run.md`。
