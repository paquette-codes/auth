<?php

declare(strict_types=1);

namespace Jasny\Auth\Tests\Confirmation;

use Jasny\Auth\Confirmation\NoConfirmation;
use Jasny\Auth\StorageInterface;
use Jasny\Auth\UserInterface as User;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

#[CoversClass(NoConfirmation::class)]
class NoConfirmationTest extends TestCase
{
    protected NoConfirmation $service;

    public function setUp(): void
    {
        $this->service = new NoConfirmation();
    }

    public function testWithSubject()
    {
        $this->assertSame($this->service, $this->service->withSubject('test'));
    }

    public function testWithLogger()
    {
        $logger = $this->createMock(LoggerInterface::class);
        $this->assertSame($this->service, $this->service->withLogger($logger));
    }

    public function testWithStorage()
    {
        $storage = $this->createMock(StorageInterface::class);
        $this->assertSame($this->service, $this->service->withStorage($storage));
    }

    public function testGetToken()
    {
        $user = $this->createMock(User::class);

        $this->expectException(\LogicException::class);
        $this->service->getToken($user, new \DateTimeImmutable());
    }

    public function testFrom()
    {
        $this->expectException(\LogicException::class);
        $this->service->from('abc');
    }
}
