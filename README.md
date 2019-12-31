Security Core
=============

Security Core was created by, and is maintained by [Graham Campbell](https://github.com/GrahamCampbell), wrapper of [voku/anti-xss](https://github.com/voku/anti-xss) for general use. Laravel wrappers for this package exist as [Laravel Security](https://github.com/GrahamCampbell/Laravel-Security) and [Laravel Binput](https://github.com/GrahamCampbell/Laravel-Binput). Feel free to check out the [change log](CHANGELOG.md), [releases](https://github.com/GrahamCampbell/Security-Core/releases), [security policy](https://github.com/GrahamCampbell/Security-Core/security/policy), [license](LICENSE), [code of conduct](.github/CODE_OF_CONDUCT.md), and [contribution guidelines](.github/CONTRIBUTING.md).

![Banner](https://user-images.githubusercontent.com/2829600/71477094-0f3c7780-27e0-11ea-8a35-139e4445155e.png)

<p align="center">
<a href="https://styleci.io/repos/163549667"><img src="https://styleci.io/repos/163549667/shield" alt="StyleCI Status"></img></a>
<a href="https://travis-ci.org/GrahamCampbell/Security-Core"><img src="https://img.shields.io/travis/GrahamCampbell/Security-Core/master.svg?style=flat-square" alt="Build Status"></img></a>
<a href="https://scrutinizer-ci.com/g/GrahamCampbell/Security-Core/code-structure"><img src="https://img.shields.io/scrutinizer/coverage/g/GrahamCampbell/Security-Core.svg?style=flat-square" alt="Coverage Status"></img></a>
<a href="https://scrutinizer-ci.com/g/GrahamCampbell/Security-Core"><img src="https://img.shields.io/scrutinizer/g/GrahamCampbell/Security-Core.svg?style=flat-square" alt="Quality Score"></img></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square" alt="Software License"></img></a>
<a href="https://github.com/GrahamCampbell/Security-Core/releases"><img src="https://img.shields.io/github/release/GrahamCampbell/Security-Core.svg?style=flat-square" alt="Latest Version"></img></a>
</p>


## Installation

Security Core requires [PHP](https://php.net) 7.0-7.4.

To get the latest version, simply require the project using [Composer](https://getcomposer.org):

```bash
$ composer require graham-campbell/security-core
```


## V1 vs V2

V1 was a port of the security class from [CodeIgniter 3](https://codeigniter.com). CodeIgniter 4 will not be keeping this class, and so V2 now functions as a wrapper of [voku/anti-xss](https://github.com/voku/anti-xss), which superseeds CodeIgniter's security class.


## Usage

To sanitize your string, simply call the `clean` method on the `Security` class.

```php
<?php

use GrahamCampbell\SecurityCore\Security;

// $clean = '<span/>X</span>';
$clean = Security::create()->clean('<span/onmouseover=confirm(1)>X</span>');
```

For usage in Laravel, check out [Laravel Security](https://github.com/GrahamCampbell/Laravel-Security) and [Laravel Binput](https://github.com/GrahamCampbell/Laravel-Binput). 


## Security

If you discover a security vulnerability within this package, please send an email to Graham Campbell at graham@alt-three.com. All security vulnerabilities will be promptly addressed. You may view our full security policy [here](https://github.com/GrahamCampbell/Security-Core/security/policy).


## License

Security Core is licensed under [The MIT License (MIT)](LICENSE).


---

<div align="center">
	<b>
		<a href="https://tidelift.com/subscription/pkg/packagist-graham-campbell-security-core?utm_source=packagist-graham-campbell-security-core&utm_medium=referral&utm_campaign=readme">Get professional support for Security Core with a Tidelift subscription</a>
	</b>
	<br>
	<sub>
		Tidelift helps make open source sustainable for maintainers while giving companies<br>assurances about security, maintenance, and licensing for their dependencies.
	</sub>
</div>
