<p align="center">
    <h1 align="center">Модель работы с сервисом Infotecs PKI Service</h1>
</p>


ТРЕБОВАНИЯ
----------

Минимальная версия PHP 5.6.0.


НАСТРОЙКА
---------

В классе Infotecs необходимо указать корректные значения констант в вашем случае

**КОНСТАНТЫ:**
- PKI_SERVICE_URL - УРЛ адрес сервиса Инфотекс
- PKI_SERVICE_LOGIN - логин пользователя сервиса Инфотекс
- PKI_SERVICE_PASSWORD - пароль пользователя сервиса Инфотекс
- PKI_COOKIE_FILE - имя локального файла для хранения кукис (необходим для корректной авторизации в сервисе)


ИСПОЛЬЗОВАНИЕ
-------------

### Методы класса

Основные примеры вызова методов класса приведены в файле index.php

**Реализованы следующие методы:**
- login() - функция логина
- get_cert_id($thumbprint) - функция получения id сертификата по отпечатку
- sign($id_cert, $content) - функция подписания строки $content 
- hash($content, $type = 'HASH_FILE_12_256') - функция получения хеша строки
- verify($data, $signature=null) - функция проверки подписи (открепленная и прикрепленная)