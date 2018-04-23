<?php
/**
 * Модель работы с сервисом Infotecs PKI Service
 *
 * @author Anton Kudryavtsev <antonsk@mail.ru>
 * Date: 10/04/18
 */

class Infotecs 
{
    const REQUEST_TYPE_POST = 'POST';
    const REQUEST_TYPE_GET = 'GET';

   const PKI_SERVICE_URL = 'http://host:port/api/';
   const PKI_SERVICE_LOGIN = 'username';
   const PKI_SERVICE_PASSWORD = 'password';
   const PKI_COOKIE_FILE = 'infotecs.txt';
   const USER_AGENT  = 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:13.0) Gecko/20100101 Firefox/13.0.1';

   const FORMAT_DER = 0;
   const TYPE_DETACHED = 1;

   // csrf токен
   private $_csrf_token;

    /**
    *  Передача запроса в API и получение ответа
    */
   public function sendRequest($method_name, $request_type = self::REQUEST_TYPE_GET,  $sendData = null)
   {
      $ch = curl_init();
      // формируем урл
      $url = self::PKI_SERVICE_URL.$method_name;
      // массив для заголовков
      $headers = [];
      // если соединяемся с https
      if(strtolower((substr($url,0,5))=='https')) { 
       curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
       curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
      }
      
      // откуда пришли на эту страницу
      curl_setopt($ch, CURLOPT_REFERER, self::PKI_SERVICE_URL);
      curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
      curl_setopt($ch, CURLOPT_USERAGENT,  self::USER_AGENT);
      // если есть данные
      if (!empty($sendData)) {
        switch(strtoupper($request_type)) {
          case self::REQUEST_TYPE_POST:
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $sendData);
            break;
          case self::REQUEST_TYPE_GET:
              $url .= '?'.http_build_query($sendData);
              break;
        }
      }
      curl_setopt($ch, CURLOPT_URL, $url);
      // добавляем csrf к заголовкам
      curl_setopt($ch, CURLOPT_HTTPHEADER, array(
           'X-XSRF-TOKEN: '.$this->_csrf_token
      ));
      // функция получения заголовков отдельно для получения csrf токена

      curl_setopt($ch, CURLOPT_HEADERFUNCTION,
        function($curl, $header) use (&$headers)
        {
          $len = strlen($header);
          $header = explode(':', $header, 2);
          if (count($header) < 2) // ignore invalid headers
            return $len;

          $name = strtolower(trim($header[0]));
          if (!array_key_exists($name, $headers))
            $headers[$name] = [trim($header[1])];
          else
            $headers[$name][] = trim($header[1]);

          return $len;
        }
      );

      curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
      //сохранять полученные COOKIE в файл
      curl_setopt($ch, CURLOPT_COOKIEJAR,  dirname(__FILE__).'/'.self::PKI_COOKIE_FILE);
      //отсылаем серверу COOKIE полученные от него при ответе 
      curl_setopt($ch, CURLOPT_COOKIEFILE, dirname(__FILE__).'/'.self::PKI_COOKIE_FILE);

      $response=curl_exec($ch);

      $result = [
        'code' => curl_getinfo($ch, CURLINFO_HTTP_CODE),
        'response' => $response,
        'response_arr' => json_decode($response, true),
        'is_json' => (json_last_error() === JSON_ERROR_NONE),
      ];

      curl_close($ch);
      // обновляем csrf
      if(isset($headers['set-cookie'])) {
        preg_match('/XSRF-TOKEN=([^;]+?);/', $headers['set-cookie'][1], $matches);
        $this->_csrf_token = $matches[1];
      }
      return $result;
   }

    /**
    *  функция логина
    */
   public function login()
   {
      $data = [
         'new_Login' => json_encode(['login'=>self::PKI_SERVICE_LOGIN, 'password'=>self::PKI_SERVICE_PASSWORD])
      ];

      return $this->sendRequest('login', self::REQUEST_TYPE_POST, $data);
   }

    /**
    *  функция получения id сертификата по отпечатку
    */
   public function get_cert_id($thumbprint)
   {
      $result = $this->sendRequest('valid_certs');

      foreach ($result['response_arr']['data'] as $certificate)
      {
          if (isset($certificate['id']) && isset($certificate['thumbPrint']))
          {
              $infotecs_thumbprint = str_replace(" ","", $certificate['thumbPrint']);
              if (strcasecmp($thumbprint, $infotecs_thumbprint) === 0)
              {
                  return $certificate['id'];
              }
          }
      }
      return false;
   }

    /**
    *  функция подписания
    */
   public function sign($id_cert, $content)
   {
      $data = [
            'file' => $content,
            'new_Sign' => json_encode([
                'id_cert' => $id_cert,
                'out_format' => self::FORMAT_DER, // Тип выходного формата (0-DER, !0-PEM)
                'sign_type' => self::TYPE_DETACHED, // Тип подписи (0-прикреплённая, 1-откреплённая, 2-xmlsig)
            ])
        ];

      return $this->sendRequest('sign', self::REQUEST_TYPE_POST, $data);
   }

    /**
    *  функция получения хеша строки
    */
   public function hash($content, $type = 'HASH_FILE_12_256')
   {
      $data = [
            'file' => $content,
      ];

      switch ($type) {
         case 'HASH_FILE_94':
              $action = 'hash_r34_11_94';
              break;
          case 'HASH_FILE_12_256':
              $action = 'hash_r34_11_2012_256';
              break;
          case 'HASH_FILE_12_512':
              $action = 'hash_r34_11_2012_512';
              break;
          default:
            return false;
      }

      return $this->sendRequest($action, self::REQUEST_TYPE_POST, $data);
   }

    /**
    *  функция проверки подписи
    */
   public function verify($data, $signature=null)
   {
       if($signature)  { // подпись открепленная нужно передать оба параметра как объекты типа file
        // определим mime type
        $mime1 = self::getMimeType($data);      
        $mime2 = self::getMimeType($signature);
        // убираем концы строк в подписи если она в формате base64 (текст)
        if ('text/plain' == $mime2) {
          $signature = self::prepareSign($signature);
        }
      
        $params= ["file\";\nContent-type:\"$mime1\";\nContent-disposition:\"form-data" => $data,
         "file\";\nContent-type:\"$mime2\";\nContent-disposition:\"form-data" => $signature];
      } else { // подпись Прикрепленная, тогда файл всего один
        $params = ['file' => $data];
      }

      return $this->sendRequest('verify_info',  self::REQUEST_TYPE_POST, $params);
   }

   /**
    *  Вспомогательная функция
    *  Получение mime_type по контенту
    */
   public static function getMimeType($content) 
   {
      if (is_a($content, 'CURLFile')) {
        return $content->getMimeType();
      }
      $finfo = new finfo(FILEINFO_MIME_TYPE);
      return $finfo->buffer($content);
  }

   /**
    *  Вспомогательная функция
    *  Подготовка содержимого файлов к отправке, если данные хранятся в файлах
    */
   public static function prepareFile($filename=null, $postname=null)
   {
      if($filename && is_file($filename)) {
         if ($postname == null) $postname =  $filename;
         if (function_exists('curl_file_create')) { // php 5.5+
           $cFile = curl_file_create($filename, mime_content_type($filename), $postname);
         } else {
           $handle  = fopen($filename, "r");
           $cFile = fread($handle, filesize($filename));
         }
         return $cFile;
       }
   }

   /**
    *  Вспомогательная функция
    *  Преобразование  base64 подписи
    */
    public static function prepareSign($content) 
    {
        // получаем содержимое файла если передан объект
        if (is_a($content, 'CURLFile')) {
          $content = file_get_contents($content->getFilename());
        }
        // убираем разбиение на строки
        return str_replace(array("\r", "\n"), '', $content);
    }

   /**
    *  Вспомогательная функция
    *  Выгрузка файла в браузер
    */
   public static function outputFile($content)
   {
      $mime = self::getMimeType($content);
      header('Content-Description: File Transfer');
      header("Content-Type: $mime");
      header('Content-Disposition: attachment');
      header('Content-Transfer-Encoding: binary');

      echo $content;
      exit;
   }

   /**
    *  Вспомогательная функция
    *  Выгрузка результатов запроса в браузер
    */
   public static function outputRes($result)
   {
      if($result['code'] != 200) {
        var_dump($result);
        exit;
      }
      if($result['is_json']) {
        header('Content-Type: application/json');
        echo $result['response'];
        exit;
      } else {
        echo $result['response'];
      }
   }

}

