# 受权数据计划与交付

字段及数据行先经过用途、地区和授权链检查，再生成计划和交付成品。完整性摘要只提供本地一致性证据，不替代实时撤权检查。

运行需要 Python 3.11 或更高版本，使用标准库与 SQLite，无需第三方包。演练中的机构、人员、交易及读数全部为本地合成数据。

## 带隐私预算的聚合交付

`rights_graph.privacy` 在普通明细交付之外提供纯 epsilon 差分隐私（Laplace 机制）的聚合发布，不开放任意明细查询。

- **相邻关系与保护单位**：相邻数据集定义为增删一个受保护主体——该主体稳定主体键对应的全部行、跨全部已冻结数据版本同时出现或消失。行数从不作为独立主体数。
- **预登记**：公共分组标签、数值上下界、直方图分箱与主体贡献上限在看数据之前登记；空组仍按公共域输出带噪结果，不会先按真实人数筛掉小组，也不会只给非空组加噪。
- **敏感度（L1，单主体增删）**：主体计数向量为 `C=max_contributions`；裁剪后总和向量为 `C*(high-low)`；直方图（分组×分箱整体向量）为 `C`。同一主体跨行先按主体归并，总和取组内裁剪均值，直方图按主体投票形成概率向量，超出上限的分组按公开序确定性裁剪。
- **预算累计**：预算按受保护主体域和预算期统一累计，换分析人、换子集或换已纳入的冻结版本都不会获得新额度。多组发布对整个向量施加一次 Laplace 噪声，发布之间按顺序组合累计 epsilon。
- **复用与原子扣额**：相同规范化请求与相同冻结输入（含摘要）复用同一发布且零扣额；上下文或统计计划改变须重新判定。新发布在一个事务内原子完成授权检查、预算扣减、计算与一次性噪声抽取，失败整体回滚——不存在“可取回结果却退回额度”，也不会静默重抽噪声。
- **随机源**：正式发布使用操作系统 CSPRNG（`secrets`），调用者无法固定；测试可经服务构造参数注入确定性随机源以核对敏感度、扣额与重试，调度接口拒绝任何调用者传入的种子。
- **授权与撤权**：计算前和成品取得时都执行现有授权链检查；预算花掉不代表仍有交付权，撤权后读取会标明 `authorized=false`，已花预算不退还。
- **误差与偏差**：每个发布附带噪声分布（尺度、均值绝对误差、标准差）、敏感度与裁剪偏差边界；不承诺带噪计数非负，也不承诺各组带噪总和与其它总量严格相等。取整、截断为非负等后处理是独立登记的确定性步骤，不另扣预算。
- **审计**：审计链只记录发布计划、预算变动与血缘摘要，精确未加噪统计量既不落库也不入审计。

服务操作包括 `privacy.domain.register`、`privacy.plan.register`、`privacy.release`、`privacy.release.get`、`privacy.budget.status`、`privacy.postprocess` 等；原有 `delivery.*`、`preview.*` 等普通入口保持不变。

## 构建与测试

```sh
python3 -m compileall -q rights_graph
python3 -m unittest discover -s tests -v
```

## 本地运行

```sh
python3 -m rights_graph --db :memory: demo --fixture fixtures/demo.json
python3 -m rights_graph --db :memory: privacy-demo --fixture fixtures/privacy_demo.json
python3 -m rights_graph --db :memory: privacy-demo --fixture fixtures/privacy_demo.json --seed 42
python3 -m rights_graph --help
```

`privacy-demo` 在本地合成的两张重叠明细表上演示：同一主体跨表只计一次、重叠请求零扣额复用、额度耗尽时的原子拒绝、撤权后成品取得被拒，以及留痕的后处理。`--seed` 仅用于可复现的测试随机源；省略时使用系统 CSPRNG。

演练使用临时数据库，不会连接远程服务。命令以 JSON 显示业务结果；测试覆盖核心状态、边界输入和错误路径。运行前可用 `python3 --version` 核对解释器版本。
