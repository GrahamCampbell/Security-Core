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

namespace GrahamCampbell\Tests\SecurityCore;

use GrahamCampbell\Analyzer\AnalysisTrait;
use PHPUnit\Framework\TestCase;

/**
 * This is the analysis test class.
 *
 * @internal
 */
final class AnalysisTest extends TestCase
{
    use AnalysisTrait;

    /**
     * Get the code paths to analyze.
     *
     * @return string[]
     */
    protected function getPaths()
    {
        return [
            \realpath(__DIR__ . '/../src'),
            \realpath(__DIR__),
        ];
    }
}
