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

use voku\helper\AntiXSS;
use voku\helper\UTF8;

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
     * @var AntiXSS
     */
    private $antiXss;

    /**
     * Create a new security instance.
     *
     * @param string[]|null $evil
     * @param string|null   $replacement
     */
    public function __construct(array $evil = null, string $replacement = null)
    {
        $evilRegex = [];
        if ($evil && $evil !== []) {
            foreach ($evil as $regex) {
                $evilRegex[$regex] = $replacement;
            }
        }

        $this->antiXss = new AntiXSS();
        $this->antiXss->setReplacement($replacement ?? '');
        $this->antiXss->addNeverAllowedRegex($evilRegex);
    }

    /**
     * @param \voku\helper\AntiXSS $antiXSS
     *
     * @return static
     */
    public function createFromAntiXss(AntiXSS $antiXSS): self
    {
        $security = new static();
        $security->antiXss = $antiXSS;

        return $security;
    }

    /**
     * XSS clean.
     *
     * @param string|string[] $str
     *
     * @return string|string[]
     */
    public function clean($str)
    {
        $str = $this->antiXss->xss_clean($str);

        // remove invisible chars anyway
        if ($this->antiXss->isXssFound() === false) {
            $str = $this->cleanInvisibleCharacters($str);
        }

        return $str;
    }

    /**
     * @param string|string[] $str
     *
     * @return string|string[]
     */
    private function cleanInvisibleCharacters($str)
    {
        if (\is_array($str)) {
            foreach ($str as $key => &$value) {
                $str[$key] = $this->cleanInvisibleCharacters($value);
            }

            return $str;
        }

        return UTF8::remove_invisible_characters($str, true, '');
    }
}
