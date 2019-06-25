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
 * This is the utils class.
 *
 * Some code in this class it taken from CodeIgniter 3.
 * See the original here: http://bit.ly/1oQnpjn.
 *
 * @author Andrey Andreev <narf@bofh.bg>
 * @author Derek Jones <derek.jones@ellislab.com>
 * @author Graham Campbell <graham@alt-three.com>
 */
class Utils
{
    /**
     * The list of HTML tags.
     *
     * @var string[]
     */
    const TAG_LIST = [
        'alert', 'area', 'prompt', 'confirm', 'applet', 'audio', 'basefont', 'base', 'behavior', 'bgsound',
        'blink', 'body', 'embed', 'expression', 'form', 'frameset', 'frame', 'head', 'html', 'ilayer',
        'iframe', 'input', 'button', 'select', 'isindex', 'layer', 'link', 'meta', 'keygen', 'object',
        'plaintext', 'style', 'script', 'textarea', 'title', 'math', 'video', 'svg', 'xml', 'xss',
    ];

    const NEVER_MATCHES = [
        'document.cookie'   => '[removed]',
        '(document).cookie' => '[removed]',
        'document.write'    => '[removed]',
        '(document).write'  => '[removed]',
        '.parentNode'       => '[removed]',
        '.innerHTML'        => '[removed]',
        '-moz-binding'      => '[removed]',
        '<!--'              => '&lt;!--',
        '-->'               => '--&gt;',
        '<![CDATA['         => '&lt;![CDATA[',
        '<comment>'         => '&lt;comment&gt;',
        '<%'                => '&lt;&#37;',
    ];

    const NEVER_REGEX = [
        'javascript\s*:',
        '(\(?document\)?|\(?window\)?(\.document)?)\.(location|on\w*)',
        'expression\s*(\(|&\#40;)',
        'vbscript\s*:',
        'wscript\s*:',
        'jscript\s*:',
        'vbs\s*:',
        'Redirect\s+30\d',
        "([\"'])?data\s*:[^\\1]*?base64[^\\1]*?,[^\\1]*?\\1?",
    ];

    /**
     * Sanitize HTML callback.
     *
     * @param string[] $evil
     *
     * @return \Closure
     */
    public static function sanitizeHtmlCallback(array $evil)
    {
        return function (array $matches) use ($evil) {
            if (empty($matches['closeTag'])) {
                return '&lt;'.$matches[1];
            }

            if (in_array(strtolower($matches['tagName']), self::TAG_LIST, true)) {
                return '&lt;'.$matches[1].'&gt;';
            }

            if (isset($matches['attributes'])) {
                $attributes = [];

                $pattern = '#'
                    .'(?<name>[^\s\042\047>/=]+)'
                    .'(?:\s*=(?<value>[^\s\042\047=><`]+|\s*\042[^\042]*\042|\s*\047[^\047]*\047|\s*(?U:[^\s\042\047=><`]*)))'
                    .'#i';

                $isEvil = '#^('.implode('|', $evil).')$#i';

                do {
                    $matches['attributes'] = preg_replace('#^[^a-z]+#i', '', $matches['attributes']);

                    if (!preg_match($pattern, $matches['attributes'], $attribute, PREG_OFFSET_CAPTURE)) {
                        break;
                    }

                    if (preg_match($isEvil, $attribute['name'][0]) || trim($attribute['value'][0]) === '') {
                        $attributes[] = 'xss=removed';
                    } else {
                        $attributes[] = $attribute[0][0];
                    }

                    $matches['attributes'] = substr(
                        $matches['attributes'],
                        $attribute[0][1] + strlen($attribute[0][0])
                    );
                } while ($matches['attributes'] !== '');

                $attributes = empty($attributes) ? '' : ' '.implode(' ', $attributes);

                return '<'.$matches['slash'].$matches['tagName'].$attributes.'>';
            }

            return $matches[0];
        };
    }

    /**
     * HTML entity decode callback.
     *
     * @param string $hash
     *
     * @return \Closure
     */
    public static function decodeEntityCallback(string $hash)
    {
        return function (array $match) use ($hash) {
            $match = preg_replace('|\&([a-z\_0-9\-]+)\=([a-z\_0-9\-/]+)|i', $hash.'\\1=\\2', $match[0]);

            return str_replace($hash, '&', self::entityDecode($match));
        };
    }

    /**
     * HTML entities decode.
     *
     * @param string $str
     *
     * @return string
     */
    private static function entityDecode(string $str)
    {
        if (strpos($str, '&') === false) {
            return $str;
        }

        static $entities;

        if ($entities === null) {
            $entities = array_map('strtolower', get_html_translation_table(HTML_ENTITIES, ENT_COMPAT | ENT_HTML5));
        }

        do {
            $original = $str;

            if (preg_match_all('/&[a-z]{2,}(?![a-z;])/i', $str, $matches)) {
                $replace = [];
                $matches = array_unique(array_map('strtolower', $matches[0]));
                foreach ($matches as &$match) {
                    if (($char = array_search($match.';', $entities, true)) !== false) {
                        $replace[$match] = $char;
                    }
                }
                $str = str_replace(array_keys($replace), array_values($replace), $str);
            }

            $str = html_entity_decode(
                preg_replace('/(&#(?:x0*[0-9a-f]{2,5}(?![0-9a-f;])|(?:0*\d{2,4}(?![0-9;]))))/iS', '$1;', $str),
                ENT_COMPAT | ENT_HTML5
            );
        } while ($original !== $str);

        return $str;
    }

    /**
     * Do never allowed.
     *
     * @param string $str
     *
     * @return string
     */
    public static function doNeverAllowed(string $str)
    {
        $str = str_replace(array_keys(self::NEVER_MATCHES), self::NEVER_MATCHES, $str);

        foreach (self::NEVER_REGEX as $val) {
            $str = preg_replace('#'.$val.'#is', '[removed]', $str);
        }

        return $str;
    }
}
