Security Core
=============

Security Core was created by, and is maintained by [Graham Campbell](https://github.com/GrahamCampbell), and is a port of the security class from [CodeIgniter 3](https://codeigniter.com) for general use. Laravel wrappers for this package exist as [Laravel Security](https://github.com/GrahamCampbell/Laravel-Security) and [Laravel Binput](https://github.com/GrahamCampbell/Laravel-Binput). Feel free to check out the [change log](CHANGELOG.md), [releases](https://github.com/GrahamCampbell/Security-Core/releases), [security policy](https://github.com/GrahamCampbell/Security-Core/security/policy), [license](LICENSE), [code of conduct](.github/CODE_OF_CONDUCT.md), and [contribution guidelines](.github/CONTRIBUTING.md).

<p align="center">
<a href="https://github.styleci.io/repos/163549667"><img src="https://github.styleci.io/repos/163549667/shield" alt="StyleCI Status"></img></a>
<a href="https://github.com/GrahamCampbell/Security-Core/actions?query=workflow%3ATests"><img src="https://img.shields.io/github/workflow/status/GrahamCampbell/Security-Core/Tests?style=flat-square" alt="Build Status"></img></a>
<a href="https://scrutinizer-ci.com/g/GrahamCampbell/Security-Core/code-structure"><img src="https://img.shields.io/scrutinizer/coverage/g/GrahamCampbell/Security-Core?style=flat-square" alt="Coverage Status"></img></a>
<a href="https://scrutinizer-ci.com/g/GrahamCampbell/Security-Core"><img src="https://img.shields.io/scrutinizer/g/GrahamCampbell/Security-Core?style=flat-square" alt="Quality Score"></img></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-brightgreen?style=flat-square" alt="Software License"></img></a>
<a href="https://github.com/GrahamCampbell/Security-Core/releases"><img src="https://img.shields.io/github/release/GrahamCampbell/Security-Core?style=flat-square" alt="Latest Version"></img></a>
</p>


## Installation

Security Core requires [PHP](https://php.net) 7.0-7.4.

To get the latest version, simply require the project using [Composer](https://getcomposer.org):

```bash
$ composer require graham-campbell/security-core:^1.0
```


## Usage

To sanitize your string, simply call the `clean` method on the `Security` class.

```php
<?php

use GrahamCampbell\SecurityCore\Security;

// $clean = '<span xss=removed>X</span>';
$clean = (new Security)->clean('<span/onmouseover=confirm(1)>X</span>');
```

For usage in Laravel, check out [Laravel Security](https://github.com/GrahamCampbell/Laravel-Security) and [Laravel Binput](https://github.com/GrahamCampbell/Laravel-Binput). 


## Security

If you discover a security vulnerability within this package, please send an email to Graham Campbell at graham@alt-three.com. All security vulnerabilities will be promptly addressed. You may view our full security policy [here](https://github.com/GrahamCampbell/Security-Core/security/policy).


## License

Security Core is licensed under [The MIT License (MIT)](LICENSE).


## For Enterprise

Available as part of the Tidelift Subscription

The maintainers of `graham-campbell/security-core` and thousands of other packages are working with Tidelift to deliver commercial support and maintenance for the open source dependencies you use to build your applications. Save time, reduce risk, and improve code health, while paying the maintainers of the exact dependencies you use. [Learn more.](https://tidelift.com/subscription/pkg/packagist-graham-campbell-security-core?utm_source=packagist-graham-campbell-security-core&utm_medium=referral&utm_campaign=enterprise&utm_term=repo)
