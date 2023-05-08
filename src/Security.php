<?php

declare(strict_types=1);

/*
 * This file is part of Security Core.
 *
 * (c) Graham Campbell <hello@gjcampbell.co.uk>
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
 * @author Graham Campbell <hello@gjcampbell.co.uk>
 * @author Lars Moelleken <lars@moelleken.org>
 */
class Security
{
    /**
     * The anti XSS instance.
     *
     * @var \voku\helper\AntiXSS
     */
    private AntiXSS $antiXss;

    /**
     * Create a new security instance.
     *
     * @param \voku\helper\AntiXSS $antiXss
     *
     * @return void
     */
    public function __construct(AntiXSS $antiXss)
    {
        $this->antiXss = $antiXss;
    }

    /**
     * Create a new security instance.
     *
     * @param array|null  $evil
     * @param string|null $replacement
     *
     * @return \GrahamCampbell\SecurityCore\Security
     */
    public static function create(array $evil = null, string $replacement = null): self
    {
        $antiXss = new AntiXSS();

        if ($replacement !== null) {
            $antiXss->setReplacement($replacement);
        }

        if ($evil !== null) {
            self::addEvilOptions($antiXss, $evil);
        }

        return new self($antiXss);
    }

    /**
     * Add the given evil options.
     *
     * @param \voku\helper\AntiXSS $antiXss
     * @param array                $evil
     *
     * @return void
     */
    private static function addEvilOptions(AntiXSS $antiXss, array $evil): void
    {
        if (isset($evil['attributes']) || isset($evil['tags'])) {
            $antiXss->addEvilAttributes($evil['attributes'] ?? []);
            $antiXss->addEvilHtmlTags($evil['tags'] ?? []);
        } else {
            $antiXss->addEvilAttributes($evil);
        }
    }

    /**
     * XSS clean.
     *
     * @param string|array $input
     *
     * @return string|array
     */
    public function clean($input): string|array
    {
        $output = $this->antiXss->xss_clean($input);

        return $output;
    }
}
