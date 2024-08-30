<?php

declare(strict_types=1);

namespace Jasny\Auth\Tests\Session;

use Jasny\Auth\Session\BearerAuth;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

#[CoversClass(BearerAuth::class)]
class BearerAuthTest extends TestCase
{
    protected function createService(string $header = ''): BearerAuth
    {
        $request = $this->createConfiguredMock(ServerRequestInterface::class, ['getHeaderLine' => $header]);

        return new BearerAuth($request);
    }


    public function testGetInfo()
    {
        $service = $this->createService('Bearer foo');

        $info = $service->getInfo();
        $this->assertEquals(['user' => 'foo', 'context' => null, 'checksum' => '', 'timestamp' => null], $info);
    }

    public function testGetInfoDefault()
    {
        $service = $this->createService('');

        $info = $service->getInfo();
        $this->assertEquals(['user' => null, 'context' => null, 'checksum' => '', 'timestamp' => null], $info);
    }

    public function testGetInfoWithBasicAuth()
    {
        $service = $this->createService('Basic QWxhZGRpbjpPcGVuU2VzYW1l');

        $info = $service->getInfo();
        $this->assertEquals(['user' => null, 'context' => null, 'checksum' => '', 'timestamp' => null], $info);
    }

    public function testGetInfoWithoutRequest()
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer xyz';
        $service = new BearerAuth();

        $info = $service->getInfo();
        $this->assertEquals(['user' => 'xyz', 'context' => null, 'checksum' => '', 'timestamp' => null], $info);
    }


    public function testPersist()
    {
        $this->expectException(\LogicException::class);
        $this->createService()->persist('foo', null, '', new \DateTimeImmutable());
    }

    public function testClear()
    {
        $this->expectException(\LogicException::class);
        $this->createService()->clear();
    }
}
