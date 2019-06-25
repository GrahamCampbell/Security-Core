<?php

declare(strict_types=1);

/*
 * This file is part of Security Core.
 *
 * (c) Graham Campbell <graham@alt-three.com>
 * (c) British Columbia Institute of Technology
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace GrahamCampbell\SecurityCore;

/**
 * This is the security class.
 *
 * Some code in this class it taken from CodeIgniter 3.
 * See the original here: http://bit.ly/1oQnpjn.
 *
 * @author Andrey Andreev <narf@bofh.bg>
 * @author Derek Jones <derek.jones@ellislab.com>
 * @author Graham Campbell <graham@alt-three.com>
 */
class Security
{
    /**
     * The evil attributes.
     *
     * @var string[]
     */
    protected $evil;

    /**
     * Create a new security instance.
     *
     * @param string[]|null $evil
     *
     * @return void
     */
    public function __construct(array $evil = null)
    {
        $this->evil = $evil ?: ['(?<!\w)on\w*', 'style', 'xmlns', 'formaction', 'form', 'xlink:href', 'FSCommand', 'seekSegmentTime'];
    }

    /**
     * XSS clean.
     *
     * @param string|string[] $str
     *
     * @return string
     */
    public function clean($str)
    {
        if (is_array($str)) {
            foreach ($str as $key => &$value) {
                $str[$key] = $this->clean($value);
            }

            return $str;
        }

        $i = 0;
        $hash = bin2hex(random_bytes(20));

        do {
            $i++;
            $processed = $this->process($str, $hash);
        } while ($i < 3 && $processed !== $str);

        return $processed;
    }

    /**
     * Process a string for cleaning.
     *
     * @param string $str
     * @param string $hash
     *
     * @return string
     */
    protected function process(string $str, string $hash)
    {
        $str = self::removeInvisibleCharacters($str);

        if (stripos($str, '%') !== false) {
            do {
                $original = $str;
                $str = preg_replace_callback(
                    '#%(?:\s*[0-9a-f]){2,}#i',
                    [$this, 'urlDecodeSpaces'],
                    rawurldecode($str)
                );
            } while ($original !== $str);

            unset($original);
        }

        $str = preg_replace_callback(
            "/[^a-z0-9>]+[a-z0-9]+=([\'\"]).*?\\1/si",
            [$this, 'convertAttribute'],
            $str
        );

        $str = preg_replace_callback(
            '/<\w+.*?(?=>|<|$)/si',
            Utils::decodeEntityCallback($hash),
            $str
        );

        $str = self::removeInvisibleCharacters($str);

        $str = str_replace("\t", ' ', $str);

        $str = Utils::doNeverAllowed($str);

        $str = str_replace(['<?', '?'.'>'], ['&lt;?', '?&gt;'], $str);

        $words = [
            'javascript', 'expression', 'vbscript', 'jscript', 'wscript',
            'vbs', 'script', 'base64', 'applet', 'alert', 'document',
            'write', 'cookie', 'window', 'confirm', 'prompt', 'eval',
        ];

        foreach ($words as $word) {
            $word = implode('\s*', str_split($word)).'\s*';
            $str = preg_replace_callback(
                '#('.substr($word, 0, -3).')(\W)#is',
                [$this, 'compactExplodedWords'],
                $str
            );
        }

        do {
            $original = $str;

            if (preg_match('/<a/i', $str)) {
                $str = preg_replace_callback(
                    '#<a[^a-z0-9>]+([^>]*?)(?:>|$)#si',
                    [$this, 'jsLinkRemoval'],
                    $str
                );
            }

            if (preg_match('/<img/i', $str)) {
                $str = preg_replace_callback(
                    '#<a(?:rea)?[^a-z0-9>]+([^>]*?)(?:>|$)#si',
                    [$this, 'jsImgRemoval'],
                    $str
                );
            }

            if (preg_match('/script|xss/i', $str)) {
                $str = preg_replace('#</*(?:script|xss).*?>#si', '[removed]', $str);
            }
        } while ($original !== $str);

        unset($original);

        $pattern = '#'
            .'<((?<slash>/*\s*)((?<tagName>[a-z0-9]+)(?=[^a-z0-9]|$)|.+)'
            .'[^\s\042\047a-z0-9>/=]*'
            .'(?<attributes>(?:[\s\042\047/=]*'
            .'[^\s\042\047>/=]+'
                .'(?:\s*='
                    .'(?:[^\s\042\047=><`]+|\s*\042[^\042]*\042|\s*\047[^\047]*\047|\s*(?U:[^\s\042\047=><`]*))'
                .')?'
            .')*)'
            .'[^>]*)(?<closeTag>\>)?#isS';

        do {
            $original = $str;
            $str = preg_replace_callback($pattern, Utils::sanitizeHtmlCallback($this->evil), $str);
        } while ($original !== $str);

        unset($original);

        $str = preg_replace(
            '#(alert|prompt|confirm|cmd|passthru|eval|exec|expression|system|fopen|fsockopen|file|file_get_contents|readfile|unlink)(\s*)\((.*?)\)#si',
            '\\1\\2&#40;\\3&#41;',
            $str
        );

        $str = preg_replace(
            '#(alert|prompt|confirm|cmd|passthru|eval|exec|expression|system|fopen|fsockopen|file|file_get_contents|readfile|unlink)(\s*)`(.*?)`#si',
            '\\1\\2&#96;\\3&#96;',
            $str
        );

        return Utils::doNeverAllowed($str);
    }

    /**
     * Removes invisible characters.
     *
     * @param string $str
     * @param bool   $urlEncoded
     *
     * @return string
     */
    private static function removeInvisibleCharacters(string $str, bool $urlEncoded = true)
    {
        $nonDisplayables = [];

        if ($urlEncoded) {
            $nonDisplayables[] = '/%0[0-8bcef]/';
            $nonDisplayables[] = '/%1[0-9a-f]/';
        }

        $nonDisplayables[] = '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+/S';

        do {
            $str = preg_replace($nonDisplayables, '', $str, -1, $count);
        } while ($count);

        return $str;
    }

    /**
     * URL decode taking spaces into account.
     *
     * @param string[] $matches
     *
     * @return string
     */
    private static function urlDecodeSpaces(array $matches)
    {
        $input = $matches[0];
        $nospaces = preg_replace('#\s+#', '', $input);

        return $nospaces === $input ? $input : rawurldecode($nospaces);
    }

    /**
     * Compact exploded words.
     *
     * @param string[] $matches
     *
     * @return string
     */
    private static function compactExplodedWords(array $matches)
    {
        return preg_replace('/\s+/s', '', $matches[1]).$matches[2];
    }

    /**
     * JS link removal.
     *
     * @param string[] $match
     *
     * @return string
     */
    private static function jsLinkRemoval(array $match)
    {
        return str_replace(
            $match[1],
            preg_replace(
                '#href=.*?(?:(?:alert|prompt|confirm)(?:\(|&\#40;|`|&\#96;)|javascript:|livescript:|mocha:|charset=|window\.|\(?document\)?\.|\.cookie|<script|<xss|d\s*a\s*t\s*a\s*:)#si',
                '',
                self::filterAttributes($match[1])
            ),
            $match[0]
        );
    }

    /**
     * JS image removal.
     *
     * @param string[] $match
     *
     * @return string
     */
    private static function jsImgRemoval(array $match)
    {
        return str_replace(
            $match[1],
            preg_replace(
                '#src=.*?(?:(?:alert|prompt|confirm|eval)(?:\(|&\#40;|`|&\#96;)|javascript:|livescript:|mocha:|charset=|window\.|\(?document\)?\.|\.cookie|<script|<xss|base64\s*,)#si',
                '',
                self::filterAttributes($match[1])
            ),
            $match[0]
        );
    }

    /**
     * Attribute conversion.
     *
     * @param string[] $match
     *
     * @return string
     */
    private static function convertAttribute(array $match)
    {
        return str_replace(['>', '<', '\\'], ['&gt;', '&lt;', '\\\\'], $match[0]);
    }

    /**
     * Attribute filtering.
     *
     * @param string $str
     *
     * @return string
     */
    private static function filterAttributes(string $str)
    {
        $out = '';

        if (preg_match_all('#\s*[a-z\-]+\s*=\s*(\042|\047)([^\\1]*?)\\1#is', $str, $matches)) {
            foreach ($matches[0] as $match) {
                $out .= preg_replace('#/\*.*?\*/#s', '', $match);
            }
        }

        return $out;
    }
}
