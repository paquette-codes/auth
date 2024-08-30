<?php

declare(strict_types=1);

namespace Jasny\Auth\Tests\Event;

use Jasny\Auth\Auth;
use Jasny\Auth\Event\AbstractEvent;
use Jasny\Auth\Event\CancellableTrait;
use Jasny\Auth\Event\Login;
use Jasny\Auth\UserInterface as User;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;

#[CoversClass(Login::class)]
#[CoversClass(AbstractEvent::class)]
#[CoversTrait(CancellableTrait::class)]
class LoginTest extends TestCase
{
    public function testGetters()
    {
        $auth = $this->createMock(Auth::class);
        $user = $this->createMock(User::class);

        $login = new Login($auth, $user);

        $this->assertSame($auth, $login->auth());
        $this->assertSame($user, $login->user());
    }

    public function testCancel()
    {
        $auth = $this->createMock(Auth::class);
        $user = $this->createMock(User::class);

        $login = new Login($auth, $user);

        $this->assertFalse($login->isCancelled());
        $this->assertFalse($login->isPropagationStopped());
        $this->assertEquals('', $login->getCancellationReason());

        $login->cancel('not ok');

        $this->assertTrue($login->isCancelled());
        $this->assertTrue($login->isPropagationStopped());
        $this->assertEquals('not ok', $login->getCancellationReason());
    }
}
