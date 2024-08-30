<?php

declare(strict_types=1);

namespace Jasny\Auth\User;

use AllowDynamicProperties;
use Jasny\Auth\ContextInterface as Context;
use Jasny\Auth\UserInterface;

/**
 * A simple user class which can be used instead of creating a custom user class.
 */
#[AllowDynamicProperties]
final class BasicUser implements UserInterface
{
    public string|int $id;
    protected string $hashedPassword = '';
    public string|int $role;

    /**
     * @inheritDoc
     */
    public function getAuthId(): string
    {
        return (string)$this->id;
    }

    /**
     * @inheritDoc
     */
    public function verifyPassword(string $password): bool
    {
        return password_verify($password, $this->hashedPassword);
    }

    /**
     * @inheritDoc
     */
    public function getAuthChecksum(): string
    {
        return hash('sha256', $this->id . $this->hashedPassword);
    }

    /**
     * @inheritDoc
     */
    public function getAuthRole(?Context $context = null): string|int
    {
        return $this->role;
    }

    /**
     * @inheritDoc
     */
    public function requiresMfa(): bool
    {
        return false;
    }

    /**
     * Factory method; create object from data loaded from DB.
     *
     * @param array<string,mixed> $data
     * @return self
     */
    public static function fromData(array $data): self
    {
        $user = new self();

        foreach ($data as $key => $value) {
            $user->{$key} = $value;
        }

        return $user;
    }
}
