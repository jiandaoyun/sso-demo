# 简道云 SSO 示例

自定义接口示例演示单点登录和登出。选一种语言运行即可。

## 联调步骤

1. 在简道云的「企业设置 → 企业安全 → 单点登录」选择「自定义接口」。本机联调时，IdP 登录接口填 `http://127.0.0.1:8080/sso`，IdP 登出接口填 `http://127.0.0.1:8080/logout`。
2. 在示例代码里填入后台生成的认证返回地址（ACS）、认证密钥、Issuer URL 和username。认证加密算法与后台保持一致。
3. 按所选语言的说明启动其中一个服务。访问企业登录入口登录。
更多配置说明见[简道云自定义接口文档](https://hc.jiandaoyun.com/open/11434)。

## 跳转校验提醒

正式接入时优先使用固定回跳地址。需要支持多个地址时，先解析 URL，再与预先配置的完整回跳地址逐一匹配。未匹配时拒绝跳转。[OWASP 开放重定向防护指南](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html#preventing-unvalidated-redirects-and-forwards)
