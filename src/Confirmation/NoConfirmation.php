<?php

declare(strict_types=1);

namespace Jasny\Auth\Confirmation;

use DateTimeInterface;
use Jasny\Auth\StorageInterface as Storage;
use Jasny\Auth\UserInterface as User;
use LogicException;
use Psr\Log\LoggerInterface as Logger;

/**
 * No support for confirmation tokens.
 */
class NoConfirmation implements ConfirmationInterface
{
    /**
     * @inheritDoc
     */
    public function withStorage(Storage $storage): static
    {
        return $this;
    }

    /**
     * @inheritDoc
     */
    public function withLogger(Logger $logger): static
    {
        return $this;
    }

    /**
     * @inheritDoc
     */
    public function withSubject(string $subject): static
    {
        return $this;
    }

    /**
     * Generate a confirmation token.
     *
     * @throws LogicException
     */
    public function getToken(User $user, DateTimeInterface $expire): string
    {
        throw new LogicException("Confirmation tokens are not supported");
    }

    /**
     * Get user by confirmation token.
     *
     * @param string $token Confirmation token
     * @return User
     * @throws LogicException
     */
    public function from(string $token): User
    {
        throw new LogicException("Confirmation tokens are not supported");
    }
}
