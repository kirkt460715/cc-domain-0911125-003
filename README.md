# 受权数据计划与交付

字段及数据行先经过用途、地区和授权链检查，再生成计划和交付成品。完整性摘要只提供本地一致性证据，不替代实时撤权检查。

运行需要 Python 3.11 或更高版本，使用标准库与 SQLite，无需第三方包。演练中的机构、人员、交易及读数全部为本地合成数据。

## 构建与测试

```sh
python3 -m compileall -q rights_graph
python3 -m unittest discover -s tests -v
```

## 本地运行

```sh
python3 -m rights_graph --db :memory: demo --fixture fixtures/demo.json
python3 -m rights_graph --help
```

演练使用临时数据库，不会连接远程服务。命令以 JSON 显示业务结果；测试覆盖核心状态、边界输入和错误路径。运行前可用 `python3 --version` 核对解释器版本。
