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

function decodeRequest(array $config, $request): array
{
   return (array) JWT::decode(
      $request,
      new Key(
         $config['secret'],
         // 与简道云中配置的 认证加密算法 保持一致
         'HS256'
      )
   );
}

function openDemoSession(): void
{
   if (!session_start([
      'use_only_cookies' => 1,
      'use_strict_mode' => 1,
      'cookie_path' => '/',
      'cookie_httponly' => 1,
      'cookie_samesite' => 'Lax',
      'cache_limiter' => ''
   ])) {
      throw new RuntimeException('Could not open the demo session.');
   }
}

function badRequest(string $message): void
{
   http_response_code(400);
   header('Content-Type: text/plain; charset=UTF-8');
   echo $message;
}

function logoutReturnUrl(array $config): string
{
   // PHP 会用最后一个值覆盖同名查询参数。读取原始查询避免接受有歧义的回程。
   $redirectUri = null;
   foreach (explode('&', $_SERVER['QUERY_STRING'] ?? '') as $parameter) {
      $pair = explode('=', $parameter, 2);
      $name = urldecode($pair[0]);
      if (strpos($name, 'redirect_uri[') === 0 || ($name === 'redirect_uri' && $redirectUri !== null)) {
         throw new UnexpectedValueException('Invalid redirect URI.');
      }
      if ($name === 'redirect_uri') {
         $redirectUri = urldecode($pair[1] ?? '');
      }
   }
   if ($redirectUri === null) {
      return $config['logout_return_url'];
   }

   $target = parse_url($redirectUri);
   if (filter_var($redirectUri, FILTER_VALIDATE_URL) === false ||
       !in_array(strtolower($target['scheme'] ?? ''), ['http', 'https'], true) ||
       isset($target['user']) || isset($target['pass'])) {
      throw new UnexpectedValueException('Invalid redirect URI.');
   }
   return $redirectUri;
}

function handleLogout(array $config): void
{
   header('Cache-Control: no-store');
   try {
      // 校验登出请求。
      $decoded = decodeRequest($config, $_GET['request'] ?? null);
      if (($decoded['type'] ?? null) !== 'slo_req') {
         throw new UnexpectedValueException('Wrong type.');
      }

      // 清除会话。
      if (isset($_COOKIE[session_name()])) {
         openDemoSession();
         $sessionId = $decoded['index'] ?? null;
         if (is_string($sessionId) && isset($_SESSION['sso_sessions'][$sessionId])) {
            if ($_SESSION['sso_sessions'][$sessionId] !== ($decoded['nameId'] ?? null)) {
               session_write_close();
               throw new UnexpectedValueException('Session member does not match.');
            }
            unset($_SESSION['sso_sessions'][$sessionId]);
         }
         session_write_close();
      }
   } catch (Throwable $error) {
      badRequest('无效的单点登出请求。');
      return;
   }

   try {
      // 校验登出地址。
      header('Location: ' . logoutReturnUrl($config), true, 303);
   } catch (UnexpectedValueException $error) {
      badRequest('无效的登出返回地址。');
   }
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
session_name('jdy_demo_session');
if (basename((string) $path) === 'logout') {
   if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
      header('Allow: GET');
      http_response_code(405);
      return;
   }
   handleLogout($config);
   return;
}

$request = $_GET['request'];
$state = $_GET['state'];
// Should Check Detail in Prod
$decoded = decodeRequest($config, $request);
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
   openDemoSession();
   $_SESSION['sso_sessions'][$sessionId] = trim($config['username']);
   session_write_close();
   header('Location: ' . $config['acs'] . '?response=' . $encoded . '&state=' . $state);
} else {
   echo 'Bad Request.';
}
die();
?>
