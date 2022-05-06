<?php
require __DIR__ . '/vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$config = [
   'acs' => 'https://www.jiandaoyun.com/sso/custom/5b4bf4398aa34804a574bfcb/acs',
   'secret' => 'fHVI4PztDMHShqZzkLbuS8hn',
   'issuer' => 'com.angelmsger',
   'username' => 'angelmsger'
];
$request = $_GET['request'];
$state = $_GET['state'];
// Should Check Detail in Prod
$decoded = (array) JWT::decode($request, new Key($config['secret'], 'HS256'));
if ($decoded['type'] == 'sso_req') {
   $encoded = JWT::encode([
       'type' => 'sso_res',
       'username' => $config['username'],
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
