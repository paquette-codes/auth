<?php

namespace Jasny\Auth\Tests\Confirmation;

use DateTime;
use DateTimeImmutable;
use Hashids\Hashids;
use Jasny\Auth\Confirmation\HashidsConfirmation;
use Jasny\Auth\Confirmation\InvalidTokenException;
use Jasny\Auth\StorageInterface as Storage;
use Jasny\Auth\UserInterface as User;
use Jasny\PHPUnit\CallbackMockTrait;
use Lcobucci\Clock\FrozenClock;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\LoggerInterface as Logger;
use RuntimeException;

#[CoversClass(HashidsConfirmation::class)]
class HashidsConfirmationTest extends TestCase
{
    use CallbackMockTrait;

    protected const TOKEN = 'o1rLAl8m28S8v34QK8V7So8nrKOrBVFjdZgOkzmguBMNzQvyjXIn6ma1Ro9Bh8L7Mk1M0';
    protected const STD_HEX = '43b87e6e92e84566b79f6f16ee4c982accec20d16bc3e46c8656bcef93dafba6202001011200003432';
    protected const OLD_HEX = '8930d6fab596adc131412a8309d5391611047dcf9dad6e106ccbb5b8ee2ae7fb202001011200003432';

    protected User & MockObject $user;
    protected Logger & MockObject $logger;
    protected ClockInterface $clock;

    public function setUp(): void
    {
        $this->user = $this->createConfiguredMock(User::class, ['getAuthId' => '42', 'getAuthChecksum' => 'xyz']);
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->clock = new FrozenClock(new DateTimeImmutable('2019-12-01T00:00:00+00:00'));
    }

    public function expectedContext(?string $uid = null, ?string $expire = null): array
    {
        return ['subject' => 'test', 'token' => substr(self::TOKEN, 0, 8) . '...']
            + ($uid !== null ? ['user' => $uid] : [])
            + ($expire !== null ? ['expire' => $expire] : []);
    }

    public function testGetToken(): void
    {
        $storage = $this->createMock(Storage::class);
        $storage->expects($this->never())->method($this->anything());

        $hashids = $this->createMock(Hashids::class);
        $hashids->expects($this->once())->method('encodeHex')
            ->with(self::STD_HEX)
            ->willReturn(self::TOKEN);

        $confirm = (new HashidsConfirmation('secret', fn() => $hashids))
            ->withStorage($storage)
            ->withSubject('test');

        $token = $confirm->getToken($this->user, new DateTime('2020-01-01T12:00:00+00:00'));

        $this->assertEquals(self::TOKEN, $token);
    }

    public function testGetTokenWithCustomUidEncoding(): void
    {
        $storage = $this->createMock(Storage::class);
        $storage->expects($this->never())->method($this->anything());

        $hex = substr(self::STD_HEX, 0, -4) . '2a';

        $hashids = $this->createMock(Hashids::class);
        $hashids->expects($this->once())->method('encodeHex')
            ->with($hex)
            ->willReturn(self::TOKEN);

        $encode = $this->createCallbackMock($this->once(), ['42'], '2a');
        $decode = $this->createCallbackMock($this->never());

        $confirm = (new HashidsConfirmation('secret', fn() => $hashids))
            ->withUidEncoded($encode, $decode)
            ->withStorage($storage)
            ->withSubject('test')
            ->withClock($this->clock);

        $token = $confirm->getToken($this->user, new DateTime('2020-01-01T12:00:00+00:00'));

        $this->assertEquals(self::TOKEN, $token);
    }

    public function testGetTokenWithInvalidUid(): void
    {
        $storage = $this->createMock(Storage::class);
        $storage->expects($this->never())->method($this->anything());

        $hashids = $this->createMock(Hashids::class);
        $hashids->expects($this->never())->method('encodeHex');

        $encode = $this->createCallbackMock($this->once(), ['42'], false);
        $decode = $this->createCallbackMock($this->never());

        $confirm = (new HashidsConfirmation('secret', fn() => $hashids))
            ->withUidEncoded($encode, $decode)
            ->withStorage($storage)
            ->withSubject('test')
            ->withClock($this->clock);

        $this->expectExceptionObject(new RuntimeException("Failed to encode uid"));

        $confirm->getToken($this->user, new DateTime('2020-01-01T12:00:00+00:00'));
    }

    protected function createService(string $hex, ?User $user = null): HashidsConfirmation
    {
        $storage = $this->createMock(Storage::class);

        if (func_num_args() > 1) {
            $storage->expects($this->once())->method('fetchUserById')
                ->with($user !== null ? $user->getAuthId() : '42')
                ->willReturn($user);
        } else {
            $storage->expects($this->never())->method('fetchUserById');
        }

        $hashids = $this->createMock(Hashids::class);
        $hashids->expects($this->never())->method('encodeHex');
        $hashids->expects($this->once())->method('decodeHex')
            ->with(self::TOKEN)
            ->willReturn($hex);

        return (new HashidsConfirmation('secret', fn() => $hashids))
            ->withStorage($storage)
            ->withLogger($this->logger)
            ->withSubject('test')
            ->withClock($this->clock);
    }

    public function testFrom(): void
    {
        $confirm = $this->createService(self::STD_HEX, $this->user);

        $this->logger->expects($this->once())->method('info')
            ->with('Verified confirmation token', $this->expectedContext('42', '2020-01-01T12:00:00+00:00'));

        $this->assertSame($this->user, $confirm->from(self::TOKEN));
    }

    public function testFromWithCustomUidEncoding(): void
    {
        $hex = substr(self::STD_HEX, 0, -4) . '2a';

        $encode = $this->createCallbackMock($this->never());
        $decode = $this->createCallbackMock($this->once(), ['2a'], '42');

        $confirm = $this->createService($hex, $this->user)
            ->withUidEncoded($encode, $decode);

        $this->logger->expects($this->once())->method('info')
            ->with('Verified confirmation token', $this->expectedContext('42', '2020-01-01T12:00:00+00:00'));

        $this->assertSame($this->user, $confirm->from(self::TOKEN));
    }

    public function testFromDeletedUser(): void
    {
        $confirm = $this->createService(self::STD_HEX, null);

        $this->expectExceptionObject(new InvalidTokenException("Token has been revoked"));

        $expectedContext = $this->expectedContext('42', '2020-01-01T12:00:00+00:00');
        $this->logger->expects($this->once())->method('debug')
            ->with('Invalid confirmation token: user not available', $expectedContext);

        $confirm->from(self::TOKEN);
    }

    public function testFromInvalidChecksum(): void
    {
        $hex = hash('sha256', '') . '20200101000000' . '3432';

        $confirm = $this->createService($hex, $this->user);

        $this->expectExceptionObject(new InvalidTokenException("Token has been revoked"));

        $expectedContext = $this->expectedContext('42', '2020-01-01T00:00:00+00:00');
        $this->logger->expects($this->once())->method('debug')
            ->with('Invalid confirmation token: bad checksum', $expectedContext);

        $confirm->from(self::TOKEN);
    }

    public function testFromInvalidToken(): void
    {
        $hex = 'nop';

        $confirm = $this->createService($hex);

        $this->expectExceptionObject(new InvalidTokenException("Invalid confirmation token"));

        $this->logger->expects($this->once())->method('debug')
            ->with('Invalid confirmation token', $this->expectedContext());

        $confirm->from(self::TOKEN);
    }

    public function testFromInvalidUid(): void
    {
        $hex = hash('sha256', '') . '20200101000000' . 'qq';

        $encode = $this->createCallbackMock($this->never());
        $decode = $this->createCallbackMock($this->once(), ['qq'], false);

        $confirm = $this->createService($hex)
            ->withUidEncoded($encode, $decode);

        $this->expectExceptionObject(new InvalidTokenException("Invalid confirmation token"));

        $this->logger->expects($this->once())->method('debug')
            ->with('Invalid confirmation token', $this->expectedContext());

        $confirm->from(self::TOKEN);
    }

    public function testFromTokenWithInvalidExpireDate(): void
    {
        $hex = hash('sha256', '') . '99999999000000' . '3432';

        $confirm = $this->createService($hex);

        $this->expectExceptionObject(new InvalidTokenException("Invalid confirmation token"));

        $this->logger->expects($this->once())->method('debug')
            ->with('Invalid confirmation token', $this->expectedContext());

        $confirm->from(self::TOKEN);
    }

    public function testFromExpiredToken(): void
    {
        $hex = '3e912b083116f9063a7e0f6fb67179c024d4419aba564f4d898b0c033dc3285b' . '20191101120000' . '3432';

        $confirm = $this->createService($hex, $this->user);

        $this->expectExceptionObject(new InvalidTokenException("Token is expired"));

        $this->logger->expects($this->once())->method('debug')
            ->with('Expired confirmation token', $this->expectedContext('42', '2019-11-01T12:00:00+00:00'));

        $confirm->from(self::TOKEN);
    }

    public function testCreateHashIdsWithCallback(): void
    {
        $storage = $this->createMock(Storage::class);
        $storage->expects($this->never())->method('fetchUserById');

        /** @var Hashids&MockObject $hashids */
        $hashids = $this->createMock(Hashids::class);

        $salt = base_convert(hash_hmac('sha256', 'test', 'secret'), 16, 36);
        $callback = $this->createCallbackMock($this->once(), [$salt], $hashids);

        $service = (new HashidsConfirmation('secret', $callback))
            ->withStorage($storage)
            ->withSubject('test')
            ->withClock($this->clock);

        $result = $service->createHashids();

        $this->assertSame($result, $hashids);
    }


    #[Group('hashids')]
    public function testCreateHashIds(): void
    {
        $storage = $this->createMock(Storage::class);
        $storage->expects($this->never())->method('fetchUserById');

        $service = (new HashidsConfirmation('secret'))
            ->withStorage($storage)
            ->withSubject('test')
            ->withClock($this->clock);

        $hashids = $service->createHashids();
        $this->assertInstanceOf(Hashids::class, $hashids);

        $token = $hashids->encodeHex(self::STD_HEX);

        $expectedToken = self::TOKEN;
        $this->assertEquals($expectedToken, $token);
    }


    #[Group('hashids')]
    #[CoversNothing]
    public function testGetTokenWithRealHashids(): void
    {
        $storage = $this->createMock(Storage::class);
        $storage->expects($this->never())->method($this->anything());

        $confirm = (new HashidsConfirmation('secret'))
            ->withStorage($storage)
            ->withSubject('test')
            ->withClock($this->clock);

        $token = $confirm->getToken($this->user, new DateTime('2020-01-01T12:00:00+00:00'));

        $expectedToken = self::TOKEN;
        $this->assertEquals($expectedToken, $token);
    }

    #[Group('hashids')]
    #[CoversNothing]
    public function testFromWithRealHashids(): void
    {
        $storage = $this->createMock(Storage::class);
        $storage->expects($this->once())->method('fetchUserById')
            ->with('42')
            ->willReturn($this->user);

        $confirm = (new HashidsConfirmation('secret'))
            ->withStorage($storage)
            ->withSubject('test')
            ->withClock($this->clock);

        $user = $confirm->from(self::TOKEN);

        $this->assertSame($this->user, $user);
    }

    #[Group('hashids')]
    #[CoversNothing]
    public function testFromOtherSubjectWithRealHashids(): void
    {
        $storage = $this->createMock(Storage::class);
        $storage->expects($this->never())->method('fetchUserById');

        $confirm = (new HashidsConfirmation('secret'))
            ->withStorage($storage)
            ->withSubject('foo-bar')
            ->withClock($this->clock);

        $this->expectException(InvalidTokenException::class);

        $confirm->from(self::TOKEN);
    }
}
