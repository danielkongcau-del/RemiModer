# Remielle Origin 视觉字节闭合：最后窄采集

## 上一轮的机械结论

封存会话：`04a4452ba1c33bb59349e2b0ddbe753a`。

- 核心视觉运行时证据已闭合：1,894 个 Effect 装配记录，1,894/1,894 五类数组完整。
- 通过游戏目录 `Container` 等值联接与静态标量签名，1,383 条记录精确提升为 386 个 Remielle Origin 特效根。
- 1,894/1,894 条灯光缓存记录完整；367 条非空，共 413 个 fader 与 826 个 control 值。
- 相机状态提交 19,367 条，EJK/IGO 拷贝差异为 0；4,728 条 Delay 模块成员关系与 V05 联接。
- 638 条销毁中，609 条与窗口内装配配对，29 条为窗口开始前已存在对象的左删失销毁，不提升为完整生命周期。
- 原始账本中的 5,672 次读取失败全部由同一回调内已经成功捕获的空上游指针解释；原始失败不删除，语义层只把对应容器解释为空。

综合报告：

- `E:\ZZZ\extracted\analysis\remielle-visual-final-analysis-15376-v3\report.json`
- `E:\ZZZ\extracted\analysis\remielle-visual-final-assetpath-join-15376-v1\assetpath-container-join.json`
- `E:\ZZZ\extracted\analysis\remielle-visual-final-synthesis-15376-v2\synthesis.json`

## 只剩两个字节级缺口

1. `WeatherConfig_MainPage_CovenantOfDayat01_NoonSunny` 的静态身份和原始序列化字节已知，但精确的 `SetOverrideWeatherConfigV2` 在上一轮显式窗口内零命中，因此反序列化后对象字节仍缺失。
2. 39 条旧布局失败中只有 `Eff_RemielleOrigin_Skill01_AirState_Back_02_Trail` 下的 `MonoEffectPluginAudio` 实际参与。四个现场实例均证明 `_effectPluginAudio != 0`，且该地址属于 `_cachedBehaviours`；但当前对象字节未捕获。

其余 38 条旧布局失败不因名字相似而声明运行时不存在；它们只是没有进入本轮精确 Remielle 根集合。

## 第一次窄采集的纠错结论

第一次窄采集会话 `e4764ec3ada79c1f7c297f79c21ac913` 已干净封存，三点均零丢失、零读取失败。它捕获了 16 条 `MonoEffectPluginAudio` 对象字节和 16 条提交身份；但全目录联接证明 5 个容器哈希都没有严格 Remielle 静态候选，目标哈希 `17269787340362078018` 的记录数为 0。

因此只能声明“同类对象字节采集机制有效”，不能声明目标旧布局实例已闭合。纠错重放：

- `E:\ZZZ\extracted\analysis\remielle-visual-byte-closure-analysis-34472-v3\report.json`（显式 supersede 旧 v1 结论）
- `legacy_audio_object_bytes = UNKNOWN_COVERAGE_GAP`
- `origin_weather = NOT_OBSERVED_IN_COVERED_WINDOW`

## 已准备的精确三点计划

计划目录：

`E:\ZZZ\extracted\analysis\remielle-visual-byte-closure-plan-20260901-v2`

三个物理点：

1. V01：先要求 `HDF+0xF0 == 17269787340362078018`，再要求 `MonoEffect+0x108 (_effectPluginAudio) != 0`；只有同时满足才记录插件 `Il2CppClass`、类名、`0x0..0xff` 当前对象字节、原生身份、cached-list 和 MonoEffect 标量签名。
2. V02：使用同一目标哈希和非空指针双谓词，只记录目标 AssetPath Container 的已提交身份。
3. V04：等待 Origin Weather 的精确原生消费者。

目标动作不是前台强化特殊技或“不切人自由落地”。游戏原生资产给出的确定链为：

`Skill03_AirState_Back -> Skill01_AirState_Back`

进入条件是 `Int_BackStageSkill == 1` 且 `FrameCount mode9 23`；Ability 链为：

`RemielleOrigin_Skill01_AirState_Back_BulletEmitter -> RemielleOrigin_Skill01_AirState_Back_Bullet -> Eff_RemielleOrigin_Skill01_AirState_Back_02_Trail`

没有相机点，没有通用 Behaviour 遍历，没有全动作路线，也没有固定时长或快照上限。

## 下一次运行方法

Weather 很可能在主页面初始化早期只提交一次，因此不能再等进入普通主界面后才装计划。下一次应：

1. 完全退出当前游戏进程。
2. 先启动本地等待器；等待器忽略旧 PID，在新进程的 UnifiedCapture 管道和 GameAssembly 就绪后立即完成进程绑定资格化并激活三点计划：

   ```powershell
   python E:\ZZZ\local-only\visual-acquisition\visual_byte_closure_ctl.py watch-arm
   ```

   等待器没有自动超时，也不是另一条注入链。
3. 再由用户通过 XXMI 正常启动游戏；XXMI 不安全模式保持关闭，注入库仍只有 `UnifiedCapture.dll`。
4. 进入主页面并打开 Remielle Origin 页面；随后进入试玩，进入相变时流并切人，让 Remielle 在后台自主行动，直到游戏原生 `Skill03_AirState_Back -> Skill01_AirState_Back` 分支至少轮转一次。
5. 退出试玩并干净停止。

若 V04 再次零命中，则结论不再是“重复整轮”，而是该函数不是当前主页面重载路径；下一步应从五个静态直接调用点向上选择实际页面初始化 callsite，或改为读取已加载的精确 Weather 对象注册表。不得凭字段名猜值。
