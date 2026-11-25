# Semantic Approval Gate for Antigravity CLI

这是一个 `PreToolUse` hook，处理 `run_command`、`read_file`、`write_file` 和 `edit_file`。它先尝试用本地规则识别常规只读调用，其余交给 Gemini 按当前用户意图判定。`allow` 继续交由 agy 原生权限策略判断；hook 也可以要求确认或拒绝。

## 安装

在 macOS 上使用。需要能运行已登录的 `agy`，以及 PATH 上的 Python 3.9 或更新版本。无需安装第三方 Python 包或复制别人的凭据。本包在 macOS、agy 1.5.16、Python 3.9.6 上通过插件清单检查和四类调用的离线测试；未测试在线模型审批或其他系统。

解压 ZIP，在解压得到的 `semantic-approval-gate` 目录的**上一级**运行：

```sh
agy plugin validate --strict ./semantic-approval-gate
agy plugin install ./semantic-approval-gate
agy plugin list
```

另开一个 `agy` 会话，输入 `/hooks` 查看是否启用。插件安装到用户级目录，对新会话生效。如果原来已在 `~/.gemini/config/hooks.json` 中配置同名 hook，请先停用旧配置，避免一次操作被审查两次。

## 使用前请确认数据范围

- 本地快速判断不调用模型。进入语义审查时，脚本会通过接收者自己的 `agy` 把待执行工具的参数、工作区路径和最近的会话片段发给 Gemini。参数可能包含源码、文件内容或凭据；脚本不会对这些内容做全面脱敏。只在允许把该类数据交给模型的环境里启用。
- 分享版默认不写本地审计日志；这不影响模型调用发送数据。审批子进程在临时目录运行，通过符号链接访问使用者自己的 macOS 钥匙串目录，不复制钥匙串文件。如果模型不可用或调用失败，脚本会请求确认。
- 它只是辅助审批，不是安全隔离层，且只覆盖列出的四种工具。保留 agy 原生沙箱和权限设置，不要用免确认模式替代它。hook 进程异常退出时，agy 仍可能继续按原有权限执行。

默认判定模型为 `gemini-3.8-flash-low`。如果自己的账号没有该模型，可以在启动 `agy` 前把 `AGY_APPROVER_MODEL` 设为 `agy models` 中有权限使用的 Gemini 模型 ID。

停用：`agy plugin disable semantic-approval-gate`。卸载：`agy plugin uninstall semantic-approval-gate`。

[Antigravity 官方 hook 文档](https://antigravity.google/docs/hooks)
