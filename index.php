<?php

require_once 'Infotecs.php';

$model = new Infotecs();
// login
$res = $model->login();

if (isset($res['error_type'])) {
  die ('Login failed');
}
// Получаем сертификат по отпечатку
$cert = $model->get_cert_id('4914a8372f6e8231bbdc97e4ef6fb46861f92738');
// получаем хеш бинарного файла
$file = $model->prepareFile(dirname(__FILE__).'/file.pdf');
$res = $model->hash($file);

$hash = $res['response_arr']['hash'];
// $model->outputFile($hash); // сохраняем если надо хэш  в браузере в файл file.txt
// подписываем хэш файла 
$res = $model->sign($cert, $hash);

$sign = $res['response'];
// $model->outputFile($res['response']); // сохраняем если надо подпись в браузере в файл signature.sig
// проверяем полученную подпись
// $hash = $model->prepareFile(dirname(__FILE__).'/file.txt'); // если надо считать хэш из файла
// $sign = $model->prepareFile(dirname(__FILE__).'/signature.sig', 'sign_file'); // если надо считать подпись из файла

$res = $model->verify($hash, $sign);
Infotecs::outputRes($res);
