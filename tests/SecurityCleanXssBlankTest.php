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

use GrahamCampbell\SecurityCore\Security;
use PHPUnit\Framework\TestCase;

/**
 * This is the security test class.
 *
 * @internal
 */
final class SecurityCleanXssBlankTest extends TestCase
{
    public function snippetProvider()
    {
        return [
            [
                'Hello, try to <script>alert(\'Hack\');</script> this site',
                '',
            ],
            [
                '<a href="&#38&#35&#49&#48&#54&#38&#35&#57&#55&#38&#35&#49&#49&#56&#38&#35&#57&#55&#38&#35&#49&#49&#53&#38&#35&#57&#57&#38&#35&#49&#49&#52&#38&#35&#49&#48&#53&#38&#35&#49&#49&#50&#38&#35&#49&#49&#54&#38&#35&#53&#56&#38&#35&#57&#57&#38&#35&#49&#49&#49&#38&#35&#49&#49&#48&#38&#35&#49&#48&#50&#38&#35&#49&#48&#53&#38&#35&#49&#49&#52&#38&#35&#49&#48&#57&#38&#35&#52&#48&#38&#35&#52&#57&#38&#35&#52&#49">Clickhere</a>',
                '',
            ],
            [
                '&foo should not include a semicolon',
                '&foo should not include a semicolon',
            ],
            [
                './<!--foo-->',
                '',
            ],
            [
                '<span/onmouseover=confirm(1)>X</span>',
                '',
            ],
            [
                '<div style="color:rgb(\'\'&#0;x:expression(alert(1))"></div>',
                '',
            ],
            [
                '<img/src=%00 id=confirm(1) onerror=eval(id)',
                '',
            ],
            [
                '<div id=confirm(1) onmouseover=eval(id)>X</div>',
                '',
            ],
            [
                '<span/onmouseover=confirm(1)>X</span>',
                '',
            ],
            [
                '<svg/contentScriptType=text/vbs><script>Execute(MsgBox(chr(88)&chr(83)&chr(83)))',
                '',
            ],
            [
                '<iframe/src="javascript:a=[alert&lpar;1&rpar;,confirm&#40;2&#41;,prompt%283%29];eval(a[0]);">',
                '',
            ],
            [
                '<div/style=content:url(data:image/svg+xml);visibility:visible onmouseover=alert(1)>x</div>',
                '',
            ],
            [
                '<script>Object.defineProperties(window,{w:{value:{f:function(){return 1}}}});confirm(w.f())</script>',
                '',
            ],
            [
                '<keygen/onfocus=prompt(1);>',
                '',
            ],
            [
                '<img/src=`%00` id=confirm(1) onerror=eval(id)',
                '',
            ],
            [
                '<img/src=`%00` onerror=this.onerror=confirm(1)',
                '',
            ],
            [
                '<iframe/src="data:text/html,<iframe%09onload=confirm(1);>">',
                '',
            ],
            [
                '<math><a/xlink:href=javascript:prompt(1)>X',
                '',
            ],
            [
                '<input/type="image"/value=""`<span/onmouseover=\'confirm(1)\'>X`</span>',
                '',
            ],
            [
                '<form/action=javascript&#x0003A;eval(setTimeout(confirm(1)))><input/type=submit>',
                '',
            ],
            [
                '<body/onload=this.onload=document.body.innerHTML=alert&lpar;1&rpar;>',
                '',
            ],
            [
                '<iframe/onload=\'javascript&#58;void&#40;1&#41;&quest;void&#40;1&#41;&#58;confirm&#40;1&#41;\'>',
                '',
            ],
            [
                '<object/type="text/x-scriptlet"/data="data:X,&#60script&#62setInterval&lpar;\'prompt(1)\',10&rpar;&#60/script&#62"></object>',
                '',
            ],
            [
                '<i<f<r<a<m<e><iframe/onload=confirm(1);></i>f>r>a>m>e>',
                '',
            ],
            [
                'http://www.<script abc>setTimeout(\'confirm(1)\',1)</script .com>',
                '',
            ],
            [
                '<style/onload    =    !-alert&#x28;1&#x29;>',
                '',
            ],
            [
                '<svg id=a /><script language=vbs for=a event=onload>alert 1</script>',
                '',
            ],
            [
                '<object/data="data&colon;X&comma;&lt;script&gt;alert&#40;1&#41;%3c&sol;script%3e">',
                '',
            ],
            [
                '<form/action=javascript&#x3A;void(1)&quest;void(1)&colon;alert(1)><input/type=\'submit\'>',
                '',
            ],
            [
                '<iframe/srcdoc=\'&lt;iframe&sol;onload&equals;confirm(&sol;&iexcl;&hearts;&xcup;&sol;)&gt;\'>',
                '',
            ],
            [
                '<meta/http-equiv="refresh"/content="0;url=javascript&Tab;:&Tab;void(alert(0))?0:0,0,prompt(0)">',
                '',
            ],
            [
                '<script src="h&Tab;t&Tab;t&Tab;p&Tab;s&colon;/&Tab;/&Tab;http://dl.dropbox.com/u/13018058/js.js"></script>',
                '',
            ],
            [
                '<style/onload=\'javascript&colon;void(0)?void(0)&colon;confirm(1)\'>',
                '',
            ],
            [
                '<svg><style>&#x7B;-o-link-source&#x3A;\'<style/onload=confirm(1)>\'&#x7D;',
                '',
            ],
            [
                '<math><solve i.e., x=2+2*2-2/2=? href="data:text/html,<script>prompt(1)</script>">X',
                '',
            ],
            [
                '<iframe/src="j&Tab;AVASCRIP&NewLine;t:\u0061ler\u0074&#x28;1&#x29;">',
                '',
            ],
            [
                '<iframe/src="javascript:void(alert(1))?alert(1):confirm(1),prompt(1)">',
                '',
            ],
            [
                '<embed/src=javascript&colon;\u0061&#x6C;&#101%72t&#x28;1&#x29;>',
                '',
            ],
            [
                '<img/src=\'http://i.imgur.com/P8mL8.jpg \' onmouseover={confirm(1)}f()>',
                '',
            ],
            [
                '<style/&Tab;/onload=;&Tab;this&Tab;.&Tab;onload=confirm(1)>',
                '',
            ],
            [
                '<embed/src=//goo.gl/nlX0P>',
                '',
            ],
            [
                '<form><button formaction=javascript:alert(1)>CLICKME',
                '',
            ],
            [
                '<script>x=\'con\';s=\'firm\';S=\'(1)\';setTimeout(x+s+S,0);</script>',
                '',
            ],
            [
                '<img/id="confirm&lpar;1&#x29;"/alt="/"src="/"onerror=eval(id&#x29;>',
                '',
            ],
            [
                '<iframe/src="data&colon;text&sol;html,<s&Tab;cr&Tab;ip&Tab;t>confirm(1)</script>">',
                '',
            ],
            [
                '<foo fscommand=case-insensitive><foo seekSegmentTime=whatever>',
                '',
            ],
            [
                '<foo onAttribute="bar">',
                '',
            ],
            [
                '<foo onAttributeWithSpaces = bar>',
                '',

            ],
            [
                '<foo prefixOnAttribute="bar">',
                '<foo prefixOnAttribute="bar">',
            ],
            [
                "\n><!-\n<b\n<c d=\"'e><iframe onload=alert(1) src=x>\n<a HREF=\"\">\n",
                '',
            ],
            [
                '<meta charset="x-imap4-modified-utf7">&<script&S1&TS&1>alert&A7&(1)&R&UA;&&<&A9&11/script&X&>',
                '',
            ],
            [
                '<!--\\x3E<img src=xxx:x onerror=javascript:alert(1)> -->',
                '',
            ],
            [
                '--><!-- --\x3E> <img src=xxx:x onerror=javascript:alert(1)> -->',
                '',
            ],
            [
                '<svg/onload=alert(1)',
                '',
            ],
        ];
    }

    /**
     * @dataProvider snippetProvider
     *
     * @param string $input
     * @param string $output
     */
    public function testCleanString(string $input, string $output)
    {
        $security = $this->getSecurity();

        $return = $security->xss_clean_blank($input);

        static::assertSame($output, $return);
    }

    public function testCleanArray()
    {
        $security = $this->getSecurity();

        $return = $security->xss_clean_blank(['test', '123', ['abc']]);

        static::assertSame(['test', '123', ['abc']], $return);
    }

    protected function getSecurity()
    {
        return new Security();
    }
}
