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
final class Security
{
    /**
     * @var AntiXSS
     */
    private $antiXss;

    /**
     * Create a new security instance.
     *
     * @param string[]|null $evil
     * @param string        $replacement
     * @param AntiXSS|null  $antiXss
     *
     * @return void
     */
    public function __construct(array $evil = null, string $replacement = '', AntiXSS $antiXss = null)
    {
        $evilRegex = [];
        if ($evil && $evil !== []) {
            foreach ($evil as $regex) {
                $evilRegex[$regex] = $replacement;
            }
        }

        if ($antiXss === null) {
            $this->antiXss = new AntiXSS();
        } else {
            $this->antiXss = $antiXss;
        }

        $this->antiXss->setReplacement($replacement);
        $this->antiXss->addNeverAllowedRegex($evilRegex);
    }

    /**
     * XSS clean
     *
     * @param string|string[] $str
     *
     * @return string|string[]
     */
    public function clean($str)
    {
        return $this->antiXss->xss_clean($str);
    }
}
