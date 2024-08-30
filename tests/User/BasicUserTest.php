<?php

declare(strict_types=1);

namespace Jasny\Auth\Tests\User;

use Jasny\Auth\User\BasicUser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\TestCase;

#[CoversClass(BasicUser::class)]
class BasicUserTest extends TestCase
{
    public function testFromData()
    {
        $user = BasicUser::fromData([
            'id' => 42,
            'username' => 'john',
            'hashedPassword' => password_hash('open', PASSWORD_BCRYPT),
            'role' => 'admin',
        ]);

        $this->assertInstanceOf(BasicUser::class, $user);

        $this->assertEquals(42, $user->id);
        $this->assertObjectHasProperty('username', $user);
        $this->assertEquals('john', $user->username);
        $this->assertEquals('admin', $user->role);

        return $user;
    }

    #[Depends('testFromData')]
    public function testGetAuthId(BasicUser $user)
    {
        $this->assertEquals('42', $user->getAuthId());
    }

    #[Depends('testFromData')]
    public function testVerifyPassword(BasicUser $user)
    {
        $this->assertTrue($user->verifyPassword('open'));

        $this->assertFalse($user->verifyPassword('fake'));
        $this->assertFalse($user->verifyPassword(''));
    }

    #[Depends('testFromData')]
    public function testRequiresMfa(BasicUser $user)
    {
        $this->assertFalse($user->requiresMfa());
    }

    public function testGetAuthChecksum()
    {
        $hashedPassword = password_hash('open', PASSWORD_BCRYPT);

        $user = BasicUser::fromData([
            'id' => 42,
            'hashedPassword' => $hashedPassword,
        ]);

        $this->assertEquals(
            hash('sha256', '42' . $hashedPassword),
            $user->getAuthChecksum()
        );
    }

    #[Depends('testFromData')]
    public function testGetAuthRole(BasicUser $user)
    {
        $this->assertEquals('admin', $user->getAuthRole());
    }
}
