<?php

declare(strict_types=1);

namespace Jasny\Auth\Confirmation;

use Closure;
use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;
use Exception;
use Hashids\Hashids;
use Jasny\Auth\UserInterface as User;
use Jasny\Auth\StorageInterface as Storage;
use Jasny\Immutable;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface as Logger;
use Psr\Log\NullLogger;
use RuntimeException;

/**
 * Generate and verify confirmation tokens using the Hashids library.
 *
 * @link http://hashids.org/php/
 */
class HashidsConfirmation implements ConfirmationInterface
{
    use Immutable\With;

    protected string $subject;
    protected string $secret;

    protected Closure $createHashids;
    protected Storage $storage;

    /** @phpstan-var Closure&callable(string $uid):(string|false) */
    protected Closure $encodeUid;
    /** @phpstan-var Closure&callable(string $uid):(string|false) */
    protected Closure $decodeUid;

    protected Logger $logger;
    protected ClockInterface $clock;

    /**
     * HashidsConfirmation constructor.
     *
     * @param string                        $secret
     * @param null|callable(string):Hashids $createHashids
     */
    public function __construct(string $secret, ?callable $createHashids = null)
    {
        $this->secret = $secret;

        $this->createHashids = $createHashids !== null
            ? $createHashids(...)
            : fn(string $salt) => new Hashids($salt);

        $this->encodeUid = function (string $uid) {
            $unpacked = unpack('H*', $uid);
            return $unpacked !== false ? $unpacked[1] : '';
        };
        $this->decodeUid = fn(string $hex) => pack('H*', $hex);

        $this->logger = new NullLogger();

        $this->clock = new class () implements ClockInterface
        {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable('now', new DateTimeZone('UTC'));
            }
        };
    }

    /**
     * Get copy with storage service.
     */
    public function withStorage(Storage $storage): static
    {
        return $this->withProperty('storage', $storage);
    }

    /**
     * Get copy with clock service. Mainly used for testing.
     */
    public function withClock(ClockInterface $clock): static
    {
        return $this->withProperty('clock', $clock);
    }

    /**
     * Get a copy with custom methods to encode/decode the uid.
     */
    public function withUidEncoded(callable $encode, callable $decode): static
    {
        return $this
            ->withProperty('encodeUid', $encode(...))
            ->withProperty('decodeUid', $decode(...));
    }

    /**
     * Get copy with logger.
     */
    public function withLogger(Logger $logger): static
    {
        return $this->withProperty('logger', $logger);
    }

    /**
     * Create a copy of this service with a specific subject.
     */
    public function withSubject(string $subject): static
    {
        return $this->withProperty('subject', $subject);
    }


    /**
     * Generate a confirmation token.
     */
    public function getToken(User $user, DateTimeInterface $expire): string
    {
        $uidHex = $this->encodeUid($user->getAuthId());
        $expireHex = self::utc($expire)->format('YmdHis');
        $checksum = $this->calcChecksum($user, $expire);

        return $this->createHashids()->encodeHex($checksum . $expireHex . $uidHex);
    }


    /**
     * Get user by confirmation token.
     *
     * @param string $token Confirmation token
     * @return User
     * @throws InvalidTokenException
     */
    public function from(string $token): User
    {
        $hex = $this->createHashids()->decodeHex($token);
        /** @var null|array{checksum:string,expire:DateTimeImmutable,uid:string} $info */
        $info = $this->extractHex($hex);

        $context = ['subject' => $this->subject, 'token' => self::partialToken($token)];

        if ($info === null) {
            $this->logger->debug('Invalid confirmation token', $context);
            throw new InvalidTokenException("Invalid confirmation token");
        }

        ['checksum' => $checksum, 'expire' => $expire, 'uid' => $uid] = $info;
        $context += ['user' => $uid, 'expire' => $expire->format('c')];

        $user = $this->fetchUserFromStorage($uid, $context);
        $this->verifyChecksum($checksum, $user, $expire, $context);
        $this->verifyNotExpired($expire, $context);

        $this->logger->info('Verified confirmation token', $context);

        return $user;
    }


    /**
     * Extract uid, expire date and checksum from hex.
     *
     * @param string $hex
     * @return null|array{checksum:string,expire:DateTimeImmutable,uid:string}
     */
    protected function extractHex(string $hex): ?array
    {
        if (strlen($hex) <= 78) {
            return null;
        }

        $checksum = substr($hex, 0, 64);
        $expireHex = substr($hex, 64, 14);
        $uidHex = substr($hex, 78);

        try {
            $uid = $this->decodeUid($uidHex);
            $expire = DateTimeImmutable::createFromFormat('YmdHis', $expireHex, new DateTimeZone('UTC'));
        } catch (Exception $exception) {
            return null;
        }

        if ($expire === false || $expire->format('YmdHis') !== $expireHex) {
            return null;
        }

        return ['checksum' => $checksum, 'expire' => $expire, 'uid' => $uid];
    }

    /**
     * Encode the uid to a hex value.
     */
    protected function encodeUid(string $uid): string
    {
        $hex = ($this->encodeUid)($uid);

        if ($hex === false) {
            throw new RuntimeException("Failed to encode uid");
        }

        return $hex;
    }

    /**
     * Decode the uid to a hex value.
     */
    protected function decodeUid(string $hex): string
    {
        $uid = ($this->decodeUid)($hex);

        if ($uid === false) {
            throw new RuntimeException("Failed to decode uid");
        }

        return $uid;
    }

    /**
     * Fetch user from storage by uid.
     *
     * @param string   $uid
     * @param string[] $context
     * @return User
     * @throws InvalidTokenException
     */
    protected function fetchUserFromStorage(string $uid, array $context): User
    {
        $user = $this->storage->fetchUserById($uid);

        if ($user === null) {
            $this->logger->debug('Invalid confirmation token: user not available', $context);
            throw new InvalidTokenException("Token has been revoked");
        }

        return $user;
    }

    /**
     * Check that the checksum from the token matches the expected checksum.
     *
     * @param string            $checksum
     * @param User              $user
     * @param DateTimeInterface $expire
     * @param string[]          $context
     * @throws InvalidTokenException
     */
    protected function verifyChecksum(string $checksum, User $user, DateTimeInterface $expire, array $context): void
    {
        $expected = $this->calcChecksum($user, $expire);

        if ($checksum !== $expected) {
            $this->logger->debug('Invalid confirmation token: bad checksum', $context);
            throw new InvalidTokenException("Token has been revoked");
        }
    }

    /**
     * Check that the token isn't expired.
     *
     * @param DateTimeInterface $expire
     * @param string[]          $context
     * @throws InvalidTokenException
     */
    protected function verifyNotExpired(DateTimeInterface $expire, array $context): void
    {
        if ($expire < $this->clock->now()) {
            $this->logger->debug('Expired confirmation token', $context);
            throw new InvalidTokenException("Token is expired");
        }
    }


    /**
     * Calculate confirmation checksum.
     */
    protected function calcChecksum(User $user, DateTimeInterface $expire): string
    {
        $parts = [
            self::utc($expire)->format('YmdHis'),
            $user->getAuthId(),
            $user->getAuthChecksum(),
        ];

        return hash_hmac('sha256', join("\0", $parts), $this->secret);
    }

    /**
     * Create a hashids service.
     */
    public function createHashids(): Hashids
    {
        $salt = base_convert(hash_hmac('sha256', $this->subject, $this->secret), 16, 36);

        return ($this->createHashids)($salt);
    }

    /**
     * Create a partial token for logging.
     */
    protected static function partialToken(string $token): string
    {
        return substr($token, 0, 8) . '...';
    }

    /**
     * Create a UTC date from a date.
     */
    protected static function utc(DateTimeInterface $date): DateTimeImmutable
    {
        return (new DateTimeImmutable())
            ->setTimestamp($date->getTimestamp())
            ->setTimezone(new DateTimeZone('UTC'));
    }
}
