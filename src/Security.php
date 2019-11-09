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

use HtmlSanitizer\Sanitizer;
use HtmlSanitizer\SanitizerInterface;
use voku\helper\AntiXSS;
use voku\helper\DomParserInterface;
use voku\helper\HtmlDomParser;

final class Security
{
    /**
     * @var HtmlDomParser
     */
    private $htmlDom;

    /**
     * @var Sanitizer
     */
    private $htmlSanitizer;

    /**
     * @var AntiXSS
     */
    private $antiXss;

    /**
     * @param null|AntiXSS $antiXss
     * @param null|SanitizerInterface $htmlSanitizer
     * @param null|DomParserInterface $htmlDom
     */
    public function __construct($antiXss = null, $htmlSanitizer = null, $htmlDom = null)
    {
        if ($htmlDom instanceof DomParserInterface) {
            $this->htmlDom = $htmlDom;
        } else {
            $this->htmlDom = new HtmlDomParser();
        }

        if ($htmlSanitizer instanceof SanitizerInterface) {
            $this->htmlSanitizer = $htmlSanitizer;
        } else {
            $this->htmlSanitizer = Sanitizer::create(['extensions' => ['basic']]);
        }

        if ($antiXss instanceof AntiXSS) {
            $this->antiXss = $antiXss;
        } else {
            $this->antiXss = new AntiXSS();
        }
    }

    /**
     * @param string|string[] $str
     *
     * @return string|string[]
     */
    public function xss_clean_blacklist($str)
    {
        return $this->antiXss->xss_clean($str);
    }

    /**
     * @param string|string[] $str
     *
     * @return string|string[]
     */
    public function xss_clean_blank($str)
    {
        $str = $this->antiXss->xss_clean($str);

        return $this->antiXss->isXssFound() ? '' : $str;
    }

    /**
     * @param string|string[] $str
     *
     * @return string|string[]
     */
    public function xss_clean_greylist($str)
    {
        if (\is_array($str)) {
            foreach ($str as $key => &$value) {
                $str[$key] = $this->xss_clean_greylist($value);
            }

            return $str;
        }

        return $this->antiXss->xss_clean(
            $this->htmlDom->loadHtml(
                $this->antiXss->xss_clean($str)
            )->html(true)
        );
    }

    /**
     * @param string|string[] $str
     *
     * @return string|string[]
     */
    public function xss_clean_whitelist($str)
    {
        if (\is_array($str)) {
            foreach ($str as $key => &$value) {
                $str[$key] = $this->xss_clean_whitelist($value);
            }

            return $str;
        }

        return $this->htmlSanitizer->sanitize($str);
    }
}
