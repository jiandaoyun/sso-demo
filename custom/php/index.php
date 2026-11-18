<?php
require __DIR__ . '/vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$config = [
   // acs：简道云中生成的认证返回地址
   'acs' => 'https://portal.finecloud.com/portal/tenant/620a31c23e7c5a00081e7acf/sso/custom/acs',
   // 未传入登出回程地址时，跳回租户登录页。
   'logout_return_url' => 'https://portal.finecloud.com/portal/tenant/620a31c23e7c5a00081e7acf/signin',
   // secret：认证密钥
   'secret' => 'fHVI4PztDMHShqZzkLbuS8hn',
   // issuer：Issuer URL
   'issuer' => 'com.angelmsger',
   // username：需要进行单点登录的成员ID
   'username' => 'angelmsger'
];

// 与简道云中配置的认证加密算法保持一致。
$key = new Key($config['secret'], 'HS256');

function badRequest(string $message): void
{
   http_response_code(400);
   header('Content-Type: text/plain; charset=UTF-8');
   echo $message;
}

function handleLogout(array $config, Key $key): void
{
   header('Cache-Control: no-store');

   // 校验登出请求。
   $request = $_GET['request'] ?? '';
   try {
      $decoded = is_string($request) ? (array) JWT::decode($request, $key) : [];
   } catch (DomainException | UnexpectedValueException $error) {
      $decoded = [];
   }
   if (($decoded['type'] ?? null) !== 'slo_req') {
      badRequest('无效的单点登出请求。');
      return;
   }

   // 简道云把登录响应中的 jti 作为登出请求的 index 传回。
   // $index = $decoded['index'] ?? null;
   // 实际接入时，可以根据index删除

   // 示例只做 URL 基本校验。redirect_uri 不在 JWT 签名范围内。
   // 实际接入时只跳转到预先配置的可信地址，避免开放重定向。详见 custom/README.md 的「跳转校验提醒」。
   $redirectUri = $_GET['redirect_uri'] ?? $config['logout_return_url'];
   $target = is_string($redirectUri) ? parse_url($redirectUri) : false;
   if ($target === false || filter_var($redirectUri, FILTER_VALIDATE_URL) === false ||
       !in_array(strtolower($target['scheme'] ?? ''), ['http', 'https'], true) ||
       isset($target['user']) || isset($target['pass'])) {
      badRequest('无效的登出返回地址。');
      return;
   }
   header('Location: ' . $redirectUri, true, 303);
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (basename((string) $path) === 'logout') {
   if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
      header('Allow: GET');
      http_response_code(405);
      return;
   }
   handleLogout($config, $key);
   return;
}

$request = $_GET['request'];
$state = $_GET['state'];
// Should Check Detail in Prod
$decoded = (array) JWT::decode($request, $key);
if ($decoded['type'] == 'sso_req') {
   $sessionId = bin2hex(random_bytes(16));
   $encoded = JWT::encode([
       'type' => 'sso_res',
       'username' => $config['username'],
       // 简道云将 jti 记录为 SSO 会话索引，用于发起单点登出。
       'jti' => $sessionId,
       // 简道云中未配置 Issuer URL 时，注释以下一行
       'iss' => $config['issuer'],
       'aud' => 'com.jiandaoyun',
       'exp' => time() + 3600
   ], $config['secret'], 'HS256');
   // 可以根据sessionId保存会话记录
   header('Location: ' . $config['acs'] . '?response=' . $encoded . '&state=' . $state);
} else {
   echo 'Bad Request.';
}
die();
?>
