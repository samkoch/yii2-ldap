Yii2 LDAP
=========

Yii2 LDAP helper class

## Installation

The PECL [mbstring](http://php.net/ldap) extension is required.

It is recommended to use [composer](https://getcomposer.org) to install the library.

```bash
$ composer require samkoch/yii2-ldap
```

## Using Ldap as a Yii component (Yii::$app->ldap)

Put the following in you application configuration (web.php and/or console.php)

    <?php 
    $config = [
    ...
    'ldap' => [
      'class' => 'samkoch/yii2ldap/Ldap',
      'config' => [
        'host' => 'ldap.example.com',
        'port' => '389',
        'domain' => 'exampledomain',
        'baseDn' => 'DC=example,
        'username' => 'user',
        'password' => 'pass',
      ],
    ],
    ...
    ?>