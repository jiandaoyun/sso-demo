<?php
require __DIR__ . '/vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$config = [
   // acs：简道云中生成的认证返回地址
   'acs' => 'https://portal.finecloud.com/portal/tenant/620a31c23e7c5a00081e7acf/sso/custom/acs',
   // secret：认证密钥
   'secret' => 'fHVI4PztDMHShqZzkLbuS8hn',
   // issuer：Issuer URL
   'issuer' => 'com.angelmsger',
   // username：需要进行单点登录的成员ID
   'username' => 'angelmsger'
];
$request = $_GET['request'];
$state = $_GET['state'];
// Should Check Detail in Prod
$decoded = (array) JWT::decode(
   $request, 
   new Key(
      $config['secret'], 
      // 与简道云中配置的 认证加密算法 保持一致
      'HS256',
));
if ($decoded['type'] == 'sso_req') {
   $encoded = JWT::encode([
       'type' => 'sso_res',
       'username' => $config['username'],
       // 简道云中未配置 Issuer URL 时，注释以下一行
       'iss' => $config['issuer'],
       'aud' => 'com.jiandaoyun',
       'exp' => time() + 3600
   ], $config['secret'], 'HS256');
   header('Location: ' . $config['acs'] . '?response=' . $encoded . '&state=' . $state);
} else {
   echo 'Bad Request.';
}
die();
?>
